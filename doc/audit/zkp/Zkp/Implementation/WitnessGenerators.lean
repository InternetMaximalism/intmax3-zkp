import Std

/-!
# Native witness-construction plans: block producer and balance prover

Sources (three files):
- `src/circuits/witness/block_witness_generator.rs` (2456 lines)
- `src/circuits/witness/balance_witness_generator.rs` (1083 lines)
- `src/circuits/witness/mod.rs` (18 lines)

These files build WITNESSES natively. They contain no circuit constraint at all:
every check below is a NATIVE ADMISSION condition performed by the Rust builder
*before* a witness value is produced, and it constrains only what this particular
builder is willing to emit. Nothing here is a circuit guarantee, and nothing here
restricts an adversary who hands a hand-made witness straight to a prover. The
model is therefore stated as ordered construction plans: inputs, the checks and
their order/precedence, the order of tree updates and state derivations, and
which witness fields are COPIED from the inputs versus DERIVED from generator
state.

This is a handwritten SEMANTIC MODEL, not a refinement proof of the Rust code,
of rustc, of plonky2, or of any circuit. No theorem here asserts proof soundness,
hash injectivity, signature validity, nullifier freshness, finality, or that an
accepted witness is safe.

## Production reachability of the harness key material (verified in source)

`src/circuits/mod.rs` declares `pub mod test_utils;` with NO `#[cfg(test)]`, and
`src/circuits/test_utils/mod.rs` is exactly
`pub use crate::circuits::witness::{balance_witness_generator, block_witness_generator};`.
Both generator modules therefore compile and are publicly reachable in ordinary
(non-test) builds. Inside `block_witness_generator.rs` the deterministic member
key derivation (`deterministic_member_falcon_keys`, `ChannelMemberKeys::deterministic`,
`ChannelMemberKeys::from_member_keys`, `TEST_ACTIVE_MEMBERS`, `test_recipient_for`)
and the key-holding registration paths (`add_channel_registration`,
`register_channel`) carry NO `#[cfg(test)]` either; the only `#[cfg(test)]` item in
the impl is `replace_local_test_signers`. `moduleEdges`/`blockGeneratorItems` pin
that declaration tree and `harness_key_material_is_production_reachable`,
`only_replace_local_test_signers_is_cfg_test` and
`deterministic_member_falcon_keys_slot_seed` make it a kernel-checked fact: every
member Falcon signing key of a channel registered through the fixture path is a
pure function of the PUBLIC channel id, and that function is reachable in a
production build. This is recorded as the named boundary
`deterministic-harness-key-derivation-is-production-reachable`; the source's own
mitigation (`holds_local_signing_keys`, the keyless
`add_channel_registration_public` path) is modeled and is what
`public_registration_holds_no_signing_key` and
`public_registration_cannot_sign_a_block` are about.

## What is modeled as an opaque callback (never derived)

`Deps` collects Poseidon/keccak hashing, Merkle roots and openings, Falcon
signing/verification/blob decoding, the aggregate-list commitment, Regev digests
and the record validator. Their outputs are values, never evidence: a returned
root is not authenticated ownership, a produced signature is not authorization,
and a changed chain value is not freshness.

## Faithfulness notes

- Rust `assert!`/`assert_eq!`/`expect`/`panic!`/integer overflow are PANICS, not
  recoverable errors. They are modeled as a distinguished `GenError.nativePanic`
  so that their ORDER relative to the recoverable `Result` checks stays visible;
  the model does not claim the Rust returns an error there.
- `add_block_with_tx_v2` clones the generator and commits only on success. That
  atomicity is modeled by `commitBlock` returning the untouched prior state on
  error (`refused_block_leaves_generator_unchanged`).
- `channel_leaf_member_root` (src/circuits/validity/block_hash_chain/update_channel_tree.rs
  :163-170) is currently the IDENTITY on its `prev_member_pubkeys_root` argument.
  Its body is pinned here, which makes `advance_registered_member_set`
  unreachable from the block path on this branch
  (`member_set_advance_is_unreachable_from_add_block`). If that callee changes,
  this model's pin is stale — named boundary `pinned-callee-body`.
- The `#[cfg(test)] mod production_boundary_tests` and the
  `#[cfg(all(test, feature = "deprecated-msu"))] mod member_set_update_production_path_tests`
  spans of block_witness_generator.rs, and `#[cfg(test)] mod tests` of
  balance_witness_generator.rs, are NOT translated (marked test-only in the maps).
- Untranslated in the maps: the wasm/native `Rc<RefCell>` vs `Arc<RwLock>` handle
  shim, `Debug` impls, `build_agg_sig_list_proof`'s plonky2 recursion (only its
  refusal precondition is modeled), and the plonky2 generic parameters of the
  balance generator.
-/

namespace Zkp.Implementation.WitnessGenerators

/-! ## Pinned constants -/

/-- `constants.rs: MAX_SIG_CLUSTER` — registered cosigner slots. -/
def maxSigCluster : Nat := 8
/-- `constants.rs: MEMBER_TREE_HEIGHT`. -/
def memberTreeHeight : Nat := 3
/-- `block_witness_generator.rs: TEST_ACTIVE_MEMBERS`. -/
def testActiveMembers : Nat := 3
/-- `constants.rs: CHANNEL_TREE_HEIGHT = CHANNEL_ID_BITS`. -/
def channelTreeHeight : Nat := 32
/-- `constants.rs: SEND_TREE_HEIGHT`. -/
def sendTreeHeight : Nat := 32
/-- `constants.rs: MAX_CHANNEL_TOKENS`. -/
def maxChannelTokens : Nat := 10
/-- `constants.rs: MAX_NUM_TRANSFERS_PER_TX = 1 << TRANSFER_TREE_HEIGHT`. -/
def maxTransfersPerTx : Nat := 64
/-- `regev/params.rs: REGEV_N`. -/
def regevN : Nat := 2048
/-- `regev/params.rs: REGEV_Q`. -/
def regevQ : Nat := 2013265921
/-- The single-byte slot encoding bound asserted in `deterministic_member_falcon_keys`. -/
def slotSeedLimit : Nat := 255
/-- `U63`/`BlockNumber` capacity: `BlockNumber::new` rejects `>= 2^63`. -/
def blockNumberLimit : Nat := 2 ^ 63
/-- `ChannelId` is a `u32` and `0` is reserved for the dummy channel. -/
def channelIdLimit : Nat := 2 ^ 32
/-- `test_recipient_for` base constant `0x3333_0000`. -/
def testRecipientBase : Nat := 0x33330000

theorem constants_pinned :
    maxSigCluster = 8 ∧ memberTreeHeight = 3 ∧ testActiveMembers = 3 ∧
      channelTreeHeight = 32 ∧ sendTreeHeight = 32 ∧ maxChannelTokens = 10 ∧
      maxTransfersPerTx = 64 ∧ regevN = 2048 ∧ regevQ = 2013265921 ∧
      slotSeedLimit = 255 ∧ channelIdLimit = 4294967296 ∧
      testRecipientBase = 858980352 :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem member_tree_height_is_log_two_of_max_sig_cluster :
    2 ^ memberTreeHeight = maxSigCluster := rfl

theorem test_active_members_below_capacity : testActiveMembers < maxSigCluster := by decide

theorem regev_q_positive : 0 < regevQ := by decide

/-! ## Declared module tree and production reachability

Models the `pub mod` / `pub use` items on the path from the crate's `circuits`
module to the two generator modules, with each item's `#[cfg(test)]` flag. Module
identities are an enum rather than strings so that reachability reduces cheaply
in the kernel. -/

inductive ModId where
  | circuits | balance | channel | testUtils | validity | withdraw | witness
  | blockWitnessGenerator | balanceWitnessGenerator
  deriving DecidableEq, Repr

/-- One `mod.rs` item: parent module, child name, its `#[cfg(test)]` flag, and
whether it is a `pub use` re-export rather than a `pub mod` declaration. -/
structure ModEdge where
  parent : ModId
  child : ModId
  cfgTest : Bool
  reexport : Bool
  deriving DecidableEq, Repr

/-- `src/circuits/mod.rs` (6 items, none `cfg(test)`), `src/circuits/witness/mod.rs`
(2 items) and `src/circuits/test_utils/mod.rs` (one `pub use` of two names). -/
def moduleEdges : List ModEdge :=
  [ ⟨.circuits, .balance, false, false⟩,
    ⟨.circuits, .channel, false, false⟩,
    ⟨.circuits, .testUtils, false, false⟩,
    ⟨.circuits, .validity, false, false⟩,
    ⟨.circuits, .withdraw, false, false⟩,
    ⟨.circuits, .witness, false, false⟩,
    ⟨.witness, .balanceWitnessGenerator, false, false⟩,
    ⟨.witness, .blockWitnessGenerator, false, false⟩,
    ⟨.testUtils, .balanceWitnessGenerator, false, true⟩,
    ⟨.testUtils, .blockWitnessGenerator, false, true⟩ ]

def childEdge (parent child : ModId) : Option ModEdge :=
  moduleEdges.find? (fun e => e.parent == parent && e.child == child)

/-- A path is reachable in a NON-test build when every edge along it exists and
carries no `#[cfg(test)]`. -/
def reachableChain : ModId → List ModId → Bool
  | _, [] => true
  | p, c :: rest =>
      match childEdge p c with
      | none => false
      | some e => !e.cfgTest && reachableChain c rest

def productionReachable (path : List ModId) : Bool := reachableChain .circuits path

theorem test_utils_declared_without_cfg_test :
    childEdge .circuits .testUtils = some ⟨.circuits, .testUtils, false, false⟩ := rfl

theorem test_utils_reexports_both_generators :
    (moduleEdges.filter (fun e => e.parent == ModId.testUtils)).map (fun e => (e.child, e.reexport))
      = [(ModId.balanceWitnessGenerator, true), (ModId.blockWitnessGenerator, true)] := rfl

theorem no_module_edge_is_cfg_test : moduleEdges.all (fun e => !e.cfgTest) = true := rfl

theorem block_witness_generator_reachable_via_test_utils :
    productionReachable [.testUtils, .blockWitnessGenerator] = true := rfl

theorem block_witness_generator_reachable_via_witness :
    productionReachable [.witness, .blockWitnessGenerator] = true := rfl

theorem balance_witness_generator_reachable_via_test_utils :
    productionReachable [.testUtils, .balanceWitnessGenerator] = true := rfl

/-! ### Item-level gates inside `block_witness_generator.rs` -/

inductive ItemGate where
  | unconditional
  | cfgTest
  deriving DecidableEq, Repr

/-- One item of the generator module: its name, its cfg gate, and whether it
derives or retains member SECRET key material. -/
structure ItemDecl where
  name : String
  gate : ItemGate
  holdsMemberSecrets : Bool
  deriving DecidableEq, Repr

/-- Items of `block_witness_generator.rs` that either derive/hold member secret
key material or exist to keep it out (`add_channel_registration_public`,
`holds_local_signing_keys`). Gates read off the source attributes. -/
def blockGeneratorItems : List ItemDecl :=
  [ ⟨"TEST_ACTIVE_MEMBERS", .unconditional, false⟩,
    ⟨"deterministic_member_falcon_keys", .unconditional, true⟩,
    ⟨"deterministic_regev_pk", .unconditional, false⟩,
    ⟨"test_recipient_for", .unconditional, false⟩,
    ⟨"ChannelMemberKeys::deterministic", .unconditional, true⟩,
    ⟨"ChannelMemberKeys::from_member_keys", .unconditional, true⟩,
    ⟨"ChannelMemberKeys::to_reg_record", .unconditional, false⟩,
    ⟨"BlockWitnessGenerator::add_channel_registration", .unconditional, true⟩,
    ⟨"BlockWitnessGenerator::add_channel_registration_keys", .unconditional, true⟩,
    ⟨"BlockWitnessGenerator::register_channel", .unconditional, true⟩,
    ⟨"BlockWitnessGenerator::add_channel_registration_public", .unconditional, false⟩,
    ⟨"BlockWitnessGenerator::holds_local_signing_keys", .unconditional, false⟩,
    ⟨"BlockWitnessGenerator::replace_local_test_signers", .cfgTest, true⟩ ]

theorem only_replace_local_test_signers_is_cfg_test :
    (blockGeneratorItems.filter (fun i => i.gate == ItemGate.cfgTest)).map (fun i => i.name)
      = ["BlockWitnessGenerator::replace_local_test_signers"] := rfl

/-- The harness key-derivation and key-retaining entry points, none of which is
`#[cfg(test)]`-gated. -/
def harnessKeyItems : List ItemDecl :=
  blockGeneratorItems.filter (fun i => i.holdsMemberSecrets && i.gate == ItemGate.unconditional)

theorem harness_key_items_named :
    harnessKeyItems.map (fun i => i.name) =
      ["deterministic_member_falcon_keys", "ChannelMemberKeys::deterministic",
       "ChannelMemberKeys::from_member_keys",
       "BlockWitnessGenerator::add_channel_registration",
       "BlockWitnessGenerator::add_channel_registration_keys",
       "BlockWitnessGenerator::register_channel"] := rfl

/-- The security-relevant conjunction: the harness key material is ungated AND
its module is reachable from `circuits` in a non-test build, through both the
`witness` declaration and the `test_utils` re-export. -/
theorem harness_key_material_is_production_reachable :
    harnessKeyItems.all (fun i => i.gate == ItemGate.unconditional) = true ∧
      productionReachable [.witness, .blockWitnessGenerator] = true ∧
      productionReachable [.testUtils, .blockWitnessGenerator] = true :=
  ⟨rfl, rfl, rfl⟩

/-! ## Shared value types

Hashes, digests and 32-byte words are opaque `Nat` identities: equality of two
modeled hashes is equality of the values the source compared, never evidence
that their preimages agree. -/

abbrev Hash := Nat

/-- Reasons a native builder refuses. One constructor per distinct refusal site,
so that check ORDER and precedence are provable. -/
inductive Reason where
  | recordInvalid
  | delegatesPresent
  | regevCountMismatch
  | regevDigestMismatch
  | alreadyRegisteredOrQueued
  | fixtureSignerCountMismatch
  | noQueuedRegistration
  | channelAlreadyOnChain
  | registrationBlockCarriesDeposits
  | txV2ArrayLength
  | channelActionSubwitnessMissing
  | channelActionSubwitnessShape
  | updatingSlotNotRegistered
  | cosignH2TagMismatch
  | cosignFundChannelMismatch
  | cosignCountMismatch
  | cosignSlotOrder
  | cosignBlobDecode
  | cosignPkgMismatch
  | noCosignaturesAndNoLocalKeys
  | missingRegevForPostingSlot
  | memberLeavesWrongLength
  | channelNotRegisteredForAdvance
  | blockNumberInFuture
  | noSendLeafForTxRoot
  | noDepositForReceiver
  | depositIndexOutOfRange
  | depositIndexMismatch
  | depositRecipientMismatch
  | newBlockRRegressed
  | txBlockAfterBlockR
  | depositBlockAfterBlockR
  | unsignedEventInSpan
  deriving DecidableEq, Repr

/-- Reasons the native code PANICS (Rust `assert!`, `expect`, `panic!`, or an
unsigned integer underflow). Not recoverable in the source. -/
inductive PanicReason where
  | slotSeedByteOverflow
  | memberKeyCapacityExceeded
  | regRecordCapacityExceeded
  | channelIdExpect
  | noFixtureKeysForPublicRegistration
  | recipientMismatchAssert
  | publicStateMismatchAssert
  | accountRootMismatchAssert
  | commitmentMismatchAssert
  | balanceMismatchAssert
  | nonceMismatchAssert
  | sendBlockUnderflow
  | balanceUnderflow
  deriving DecidableEq, Repr

inductive GenError where
  | tooManyKeyIds (len : Nat)
  | channelIdError
  | blockError
  | blockNumberError
  | invalidRequest (reason : Reason)
  | nativePanic (reason : PanicReason)
  deriving DecidableEq, Repr

abbrev Res (α : Type) := Except GenError α

def refuse (r : Reason) : GenError := .invalidRequest r
def panicWith (r : PanicReason) : GenError := .nativePanic r

/-! ### Except plumbing (local copies of the standard peeling lemmas) -/

def check (condition : Bool) (error : GenError) : Res Unit :=
  if condition then .ok () else .error error

theorem check_ok_iff (condition : Bool) (error : GenError) :
    check condition error = .ok () ↔ condition = true := by
  cases condition <;> simp [check]

theorem bind_ok_iff {α β : Type} (r : Res α) (f : α → Res β) (value : β) :
    (r >>= f) = .ok value ↔ ∃ x, r = .ok x ∧ f x = .ok value := by
  cases r <;> simp [Bind.bind, Except.bind]

theorem unit_bind_ok_iff {α : Type} (r : Res Unit) (s : Res α) (value : α) :
    (r >>= fun _ => s) = .ok value ↔ r = .ok () ∧ s = .ok value := by
  cases r with
  | error e => simp [Bind.bind, Except.bind]
  | ok u => cases u; simp [Bind.bind, Except.bind]

theorem exists_unit (p : Unit → Prop) : (∃ x, p x) ↔ p () := by
  constructor
  · rintro ⟨⟨⟩, h⟩; exact h
  · intro h; exact ⟨(), h⟩

theorem throw_ok_iff_false {α : Type} (e : GenError) (value : α) :
    (Except.error e : Res α) = .ok value ↔ False := by simp

theorem pure_ok_iff {α : Type} (x value : α) :
    (pure x : Res α) = .ok value ↔ x = value := by
  simp [pure, Except.pure]

/-! ### Small association-list helpers (the generator's `HashMap`s) -/

def mapGet? {α : Type} (m : List (Nat × α)) (k : Nat) : Option α :=
  (m.find? (fun p => p.1 == k)).map (fun p => p.2)

def mapContains {α : Type} (m : List (Nat × α)) (k : Nat) : Bool :=
  (mapGet? m k).isSome

def mapInsert {α : Type} (m : List (Nat × α)) (k : Nat) (v : α) : List (Nat × α) :=
  m.filter (fun p => p.1 != k) ++ [(k, v)]

def mapErase {α : Type} (m : List (Nat × α)) (k : Nat) : List (Nat × α) :=
  m.filter (fun p => p.1 != k)

theorem map_get_insert_self {α : Type} (m : List (Nat × α)) (k : Nat) (v : α) :
    mapGet? (mapInsert m k v) k = some v := by
  induction m with
  | nil => simp [mapInsert, mapGet?]
  | cons p ps ih =>
      by_cases h : p.1 = k
      · simp [mapInsert, h] at ih ⊢
        simpa [mapInsert] using ih
      · simp [mapInsert, mapGet?, h] at ih ⊢
        simpa [mapInsert, mapGet?, h] using ih

theorem map_contains_of_insert {α : Type} (m : List (Nat × α)) (k : Nat) (v : α) :
    mapContains (mapInsert m k v) k = true := by
  simp [mapContains, map_get_insert_self]

theorem map_get_erase_self {α : Type} (m : List (Nat × α)) (k : Nat) :
    mapGet? (mapErase m k) k = none := by
  induction m with
  | nil => simp [mapErase, mapGet?]
  | cons p ps ih =>
      by_cases h : p.1 = k
      · simpa [mapErase, mapGet?, h] using ih
      · simpa [mapErase, mapGet?, h] using ih

end Zkp.Implementation.WitnessGenerators
