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

/-- `0..n` as an explicit list (this Std has no `List.range` lemmas). Models the
`(0..n)` iterators the generators fold over. -/
def indicesFrom (start : Nat) : Nat → List Nat
  | 0 => []
  | n + 1 => start :: indicesFrom (start + 1) n

def indices (n : Nat) : List Nat := indicesFrom 0 n

theorem indices_from_length (s n : Nat) : (indicesFrom s n).length = n := by
  induction n generalizing s with
  | zero => rfl
  | succ n ih => simp [indicesFrom, ih]

theorem indices_length (n : Nat) : (indices n).length = n := indices_from_length 0 n

theorem indices_from_get (s n i : Nat) (h : i < n) : (indicesFrom s n)[i]? = some (s + i) := by
  induction n generalizing s i with
  | zero => omega
  | succ n ih =>
      cases i with
      | zero => simp [indicesFrom]
      | succ i =>
          have inner : i < n := by omega
          simp [indicesFrom, ih (s + 1) i inner]
          omega

theorem indices_get (n i : Nat) (h : i < n) : (indices n)[i]? = some i := by
  simpa using indices_from_get 0 n i h

theorem map_get_erase_self {α : Type} (m : List (Nat × α)) (k : Nat) :
    mapGet? (mapErase m k) k = none := by
  induction m with
  | nil => simp [mapErase, mapGet?]
  | cons p ps ih =>
      by_cases h : p.1 = k
      · simpa [mapErase, mapGet?, h] using ih
      · simpa [mapErase, mapGet?, h] using ih

/-! ## Block-producer value types -/

/-- `key_tree::MemberLeaf` — the three Poseidon identities committed per slot. -/
structure MemberLeaf where
  pkG : Hash
  pkB : Hash
  regevDigest : Hash
  deriving DecidableEq, Repr

def emptyMemberLeaf : MemberLeaf := ⟨0, 0, 0⟩

/-- `channel_registration::MemberRegEntry`. `recipient` enters the keccak
preimage only, never the Poseidon member tree. -/
structure MemberRegEntry where
  pkG : Hash
  pkB : Hash
  regevDigest : Hash
  recipient : Nat
  deriving DecidableEq, Repr

def defaultMemberRegEntry : MemberRegEntry := ⟨0, 0, 0, 0⟩

/-- `channel_registration::ChannelRegRecord`; `members` has `MAX_SIG_CLUSTER` slots. -/
structure ChannelRegRecord where
  channelId : Nat
  bpMemberSlot : Nat
  memberCount : Nat
  delegateCount : Nat
  members : List MemberRegEntry
  deriving DecidableEq, Repr

/-- `regev::RegevPk` — the two coefficient vectors of length `REGEV_N`. -/
structure RegevPk where
  a : List Nat
  b : List Nat
  deriving DecidableEq, Repr

/-- `channel_tree::ChannelLeaf`. -/
structure ChannelLeaf where
  index : Nat
  prev : Nat
  sendTreeRoot : Hash
  memberRoot : Hash
  deriving DecidableEq, Repr

def defaultChannelLeaf : ChannelLeaf := ⟨0, 0, 0, 0⟩

/-- `channel_tree::SendLeaf`. -/
structure SendLeaf where
  prev : Nat
  cur : Nat
  txTreeRoot : Hash
  deriving DecidableEq, Repr

/-- `deposit::Deposit`. -/
structure Deposit where
  depositIndex : Nat
  depositor : Nat
  recipient : Hash
  tokenIndex : Nat
  amount : Nat
  blockNumber : Nat
  auxData : Hash
  deriving DecidableEq, Repr

inductive TxClass where
  | userTransfer
  | channelAction
  deriving DecidableEq, Repr

/-- `tx::TxV2`. -/
structure TxV2 where
  txClass : TxClass
  transferTreeRoot : Hash
  nonce : Nat
  channelActionRoot : Hash
  deriving DecidableEq, Repr

def defaultTxV2 : TxV2 := ⟨.userTransfer, 0, 0, 0⟩

inductive ChannelActionKind where
  | interChannelSend
  | memberSetUpdate
  deriving DecidableEq, Repr

/-- `tx::ChannelAction`. `ChannelAction::default()` has kind `InterChannelSend`;
that default is exactly what the processor substitutes when the producer leaves
the sub-witness `None`. -/
structure ChannelAction where
  kind : ChannelActionKind
  payloadHash : Hash
  deriving DecidableEq, Repr

def defaultChannelAction : ChannelAction := ⟨.interChannelSend, 0⟩

/-- `channel_state_message::ChannelStateMessageFields`, the IMCH preimage the
members sign. -/
structure ChannelStateFields where
  epoch : Nat
  smallBlockNumber : Nat
  closeFreezeNonce : Nat
  fundAmounts : List Nat
  fundIntmaxStateRoot : Hash
  balanceStateH1 : Hash
  sharedNativeNullifierRoot : Hash
  unallocatedConfirmedIncoming : Nat
  prevDigest : Hash
  stateVersion : Nat
  deriving DecidableEq, Repr

def defaultChannelStateFields : ChannelStateFields :=
  ⟨0, 0, 0, List.replicate maxChannelTokens 0, 0, 0, 0, 0, 0, 0⟩

/-- `common::block::Block`; `key_ids` is padded to `num_users` by `Block::new`. -/
structure Block where
  numUsers : Nat
  channelId : Nat
  timestamp : Nat
  keyIds : List Nat
  txTreeRoot : Hash
  depositHashChain : Hash
  channelRegHashChain : Hash
  deriving DecidableEq, Repr

/-- `PublicState`. -/
structure PublicState where
  blockNumber : Nat
  timestamp : Nat
  accountTreeRoot : Hash
  depositTreeRoot : Hash
  prevPublicStateRoot : Hash
  deriving DecidableEq, Repr

/-- `ext_public_state::ExtendedPublicState`. -/
structure ExtPublicState where
  inner : PublicState
  blockHashChain : Hash
  depositHashChain : Hash
  depositCount : Nat
  channelRegHashChain : Hash
  bpSigChain : Hash
  deriving DecidableEq, Repr

/-- A Falcon key is modeled by its 32-byte seed (fixture path) or by an opaque
handle id (wallet path). Secret material is never derived here; only the
DERIVATION FUNCTION's inputs are modeled. -/
inductive FalconKey where
  | fromSeed (seed : List Nat)
  | handle (id : Nat)
  deriving DecidableEq, Repr

/-- An encoded cosignature blob as it arrives from a member. -/
structure CosignBlob where
  bytes : List Nat
  deriving DecidableEq, Repr

/-- `common::channel::MemberSignature`. -/
structure MemberSignature where
  memberSlot : Nat
  pkG : Hash
  signature : CosignBlob
  deriving DecidableEq, Repr

/-- The wallet's co-signed state, projected to the fields the generator reads. -/
structure CosignedState where
  channelId : Nat
  fundChannelId : Nat
  h2Tag : Hash
  fields : ChannelStateFields
  deriving DecidableEq, Repr

/-- `ChannelCosignBundle`. -/
structure CosignBundle where
  state : CosignedState
  signatures : List MemberSignature
  deriving DecidableEq, Repr

/-- The gadget witness `FalconSigGadgetWitness::for_signature(&h, digest, &sig)`. -/
structure SigWitness where
  publicPoly : Hash
  message : Hash
  signature : CosignBlob
  deriving DecidableEq, Repr

/-- `BpSigEvent` — one recorded N-of-N signing event. -/
structure BpSigEvent where
  digest : Hash
  signerPks : List Hash
  witnesses : List SigWitness
  deriving DecidableEq, Repr

/-- `RegisteredChannelPublicData` — deliberately holds no secret. -/
structure RegisteredPublic where
  regevPks : List RegevPk
  memberTree : List MemberLeaf
  memberCount : Nat
  deriving DecidableEq, Repr

/-- `ChannelMemberKeys` — the fixture-only bundle that DOES hold every member's
Falcon key. -/
structure ChannelMemberKeys where
  falconKeys : List FalconKey
  babyKeys : List Nat
  regevPks : List RegevPk
  memberTree : List MemberLeaf
  deriving DecidableEq, Repr

/-- Per-slot TxV2 witness (`BlockTxV2Witness`). -/
structure BlockTxV2Witness where
  txV2Indices : List Nat
  txV2s : List TxV2
  txV2MerkleProofs : List Hash
  newMemberLeaves : Option (List MemberLeaf)
  channelActionIndices : Option (List Nat)
  channelActions : Option (List ChannelAction)
  channelActionMerkleProofs : Option (List Hash)
  deriving DecidableEq, Repr

/-- The stored `BlockHashChainProcessorWitness`, restricted to the fields the
generator decides. -/
structure BlockWitness where
  depositStepWitness : List (Deposit × Hash)
  channelRegStepWitness : List (ChannelRegRecord × Hash)
  block : Block
  prevAccountLeaves : List ChannelLeaf
  userMerkleProofs : List Hash
  sendMerkleProofs : List Hash
  publicStateMerkleProof : Hash
  memberLeaves : Option (List MemberLeaf)
  newMemberLeaves : Option (List MemberLeaf)
  signerCount : Option Nat
  memberRegevPks : Option (List RegevPk)
  channelStateFields : Option ChannelStateFields
  txV2Indices : Option (List Nat)
  txV2s : Option (List TxV2)
  txV2MerkleProofs : Option (List Hash)
  channelActionIndices : Option (List Nat)
  channelActions : Option (List ChannelAction)
  channelActionMerkleProofs : Option (List Hash)
  deriving DecidableEq, Repr

/-- `SendStatus`. -/
structure SendStatus where
  lastSendBlock : Nat
  nextSendBlock : Option Nat
  deriving DecidableEq, Repr

/-- `account_state::AccountState`. -/
structure AccountState where
  channelId : Nat
  accountTreeRoot : Hash
  sendLeaf : SendLeaf
  sendLeafIndex : Nat
  sendMerkleProof : Hash
  channelLeaf : ChannelLeaf
  userMerkleProof : Hash
  deriving DecidableEq, Repr

/-- `update_public_state::UpdatePublicState`. -/
structure UpdatePublicState where
  new : PublicState
  old : PublicState
  merkleProof : Option Hash
  deriving DecidableEq, Repr

/-! ## Opaque dependencies

Every field is a callback whose semantics comes from another crate/module. A
value returned here is data, never evidence. -/

structure Deps where
  /-- Poseidon member-tree root over the `MAX_SIG_CLUSTER` leaves. -/
  memberRoot : List MemberLeaf → Hash
  /-- `RegevPk::poseidon_digest`. -/
  regevDigest : RegevPk → Hash
  /-- `Bytes32::reduce_to_hash_out` (canonical for a Poseidon-hash-out word). -/
  reduceToHashOut : Hash → Hash
  /-- `ChannelRegRecord::validate`. -/
  validateRecord : ChannelRegRecord → Bool
  /-- `ChannelRegRecord::hash_with_prev_hash` (keccak chain step). -/
  hashRecordWithPrev : ChannelRegRecord → Hash → Hash
  /-- `Block::hash_with_prev_hash`. -/
  hashBlockWithPrev : Block → Hash → Hash
  /-- `Deposit::hash_with_prev_hash`. -/
  hashDepositWithPrev : Deposit → Hash → Hash
  /-- `Deposit::nullifier`. -/
  depositNullifier : Deposit → Hash
  /-- Merkle openings: channel tree, send tree, deposit tree, public-state tree. -/
  channelProof : List (Nat × ChannelLeaf) → Nat → Hash
  channelTreeRoot : List (Nat × ChannelLeaf) → Hash
  sendProof : List SendLeaf → Nat → Hash
  sendRootWith : List SendLeaf → SendLeaf → Nat → Hash
  depositProof : List Deposit → Nat → Hash
  depositTreeRoot : List Deposit → Hash
  publicStateProof : List PublicState → Nat → Hash
  publicStateRoot : List PublicState → Hash
  /-- `ChannelStateMessageFields::signing_digest(channel_id, h2_tag)`. -/
  signingDigest : ChannelStateFields → Nat → Hash → Hash
  /-- `ChannelStateMessageFields::from_channel_state` — DROPS `channel_fund.channel_id`. -/
  fromChannelState : CosignedState → ChannelStateFields
  /-- `FalconKeys::pk_g` and its coefficient view. -/
  falconPkG : FalconKey → Hash
  falconPkCoefficients : FalconKey → Hash
  /-- `FalconKeys::sign`. Produces a signature; it is NOT authorization. -/
  falconSign : FalconKey → Hash → CosignBlob
  /-- `falcon_sig::decode_cosign_blob` — `none` models the decode error. -/
  decodeCosignBlob : CosignBlob → Option (CosignBlob × Hash)
  /-- `falcon_sig::falcon_pk_digest`. -/
  falconPkDigest : Hash → Hash
  /-- `falcon_sig::agg_list::agg_list_commitment`. -/
  aggListCommitment : List (Hash × List Hash) → Hash
  /-- `BabyBearSecretKey::random(seeded rng)` then `public_key().to_bytes32()`. -/
  babyPkFromSeed : Nat → Hash

/-! ## The deterministic harness key derivation (production reachable)

`deterministic_member_falcon_keys(channel_id, n)` builds `n` seeds, each a pure
function of the PUBLIC `channel_id` and the slot index. -/

/-- Byte `i` of the slot seed: `s[0..4] = channel_id.to_le_bytes()`, `s[8] = 0xfa`,
`s[31] = slot as u8 + 1`, every other byte zero. The `as u8` cast is the modulus. -/
def falconSeedByte (channelId slot i : Nat) : Nat :=
  if i < 4 then (channelId / 256 ^ i) % 256
  else if i = 8 then 0xfa
  else if i = 31 then (slot % 256 + 1) % 256
  else 0

def falconSeed (channelId slot : Nat) : List Nat :=
  (indices 32).map (falconSeedByte channelId slot)

/-- The `assert!(slot < 255, ...)` in the source is a PANIC, modeled as
`nativePanic .slotSeedByteOverflow`. -/
def deterministicMemberFalconKeys (channelId n : Nat) : Res (List FalconKey) :=
  if n ≤ slotSeedLimit then
    .ok ((indices n).map (fun slot => FalconKey.fromSeed (falconSeed channelId slot)))
  else .error (panicWith .slotSeedByteOverflow)

theorem deterministic_member_falcon_keys_slot_seed
    (channelId n slot : Nat) (small : n ≤ slotSeedLimit) (inRange : slot < n) :
    (deterministicMemberFalconKeys channelId n).toOption.bind (fun ks => ks[slot]?)
      = some (FalconKey.fromSeed (falconSeed channelId slot)) := by
  simp only [deterministicMemberFalconKeys, small, if_pos, Except.toOption, Option.bind,
    List.getElem?_map, indices_get n slot inRange, Option.map]

theorem deterministic_member_falcon_keys_panics_above_the_byte_limit
    (channelId n : Nat) (big : slotSeedLimit < n) :
    deterministicMemberFalconKeys channelId n = .error (panicWith .slotSeedByteOverflow) := by
  simp [deterministicMemberFalconKeys, Nat.not_le.mpr big]

/-- Two distinct slots below the byte limit get distinct seeds — byte 31 alone
separates them. -/
theorem falcon_seed_byte_separates_slots_below_the_limit
    (channelId s t : Nat) (hs : s < slotSeedLimit) (ht : t < slotSeedLimit) (ne : s ≠ t) :
    falconSeedByte channelId s 31 ≠ falconSeedByte channelId t 31 := by
  simp only [slotSeedLimit] at hs ht
  have hs' : s % 256 = s := Nat.mod_eq_of_lt (by omega)
  have ht' : t % 256 = t := Nat.mod_eq_of_lt (by omega)
  have hs2 : (s + 1) % 256 = s + 1 := Nat.mod_eq_of_lt (by omega)
  have ht2 : (t + 1) % 256 = t + 1 := Nat.mod_eq_of_lt (by omega)
  have e1 : falconSeedByte channelId s 31 = s + 1 := by
    unfold falconSeedByte
    rw [if_neg (by decide : ¬ (31 < 4)), if_neg (by decide : ¬ (31 = 8)), if_pos rfl, hs', hs2]
  have e2 : falconSeedByte channelId t 31 = t + 1 := by
    unfold falconSeedByte
    rw [if_neg (by decide : ¬ (31 < 4)), if_neg (by decide : ¬ (31 = 8)), if_pos rfl, ht', ht2]
  rw [e1, e2]
  omega

/-- Why the assert is load-bearing: the slot rides ONE byte, so slot 0 and slot
256 would collide into one identity if the bound were removed. -/
theorem falcon_seed_byte_wraps_at_two_hundred_fifty_six (channelId : Nat) :
    falconSeedByte channelId 0 31 = falconSeedByte channelId 256 31 := by
  simp [falconSeedByte]

/-- `test_recipient_for(channel_id, slot)`: five identical wrapping-`u32` limbs. -/
def testRecipientLimb (channelId slot : Nat) : Nat :=
  (testRecipientBase + channelId * 16 + slot) % channelIdLimit

def testRecipientFor (channelId slot : Nat) : List Nat :=
  List.replicate 5 (testRecipientLimb channelId slot)

/-- Nonzero (the property `BalanceState::validate` / `registerChannel` rely on)
whenever the wrapping add does not wrap. -/
theorem test_recipient_limb_nonzero_without_wraparound
    (channelId slot : Nat) (noWrap : testRecipientBase + channelId * 16 + slot < channelIdLimit) :
    testRecipientLimb channelId slot ≠ 0 := by
  have : testRecipientLimb channelId slot = testRecipientBase + channelId * 16 + slot :=
    Nat.mod_eq_of_lt noWrap
  simp only [this, testRecipientBase]
  omega

/-- The recipient is a pure function of the public `(channel_id, slot)`. -/
theorem test_recipient_is_a_public_function (channelId slot : Nat) :
    testRecipientFor channelId slot = List.replicate 5 (testRecipientLimb channelId slot) := rfl

/-- `deterministic_regev_pk(seed)` — canonical coefficients, all `< REGEV_Q`. -/
def deterministicRegevPk (seed : Nat) : RegevPk :=
  { a := (indices regevN).map (fun i => (seed * 2654435761 + i) % regevQ),
    b := (indices regevN).map (fun i => (seed * 40503 + 1000 + i) % regevQ) }

theorem deterministic_regev_coefficients_are_canonical (seed : Nat) :
    (∀ x ∈ (deterministicRegevPk seed).a, x < regevQ) ∧
      (∀ x ∈ (deterministicRegevPk seed).b, x < regevQ) := by
  constructor <;>
    · intro x hx
      simp only [deterministicRegevPk, List.mem_map] at hx
      obtain ⟨i, _, rfl⟩ := hx
      exact Nat.mod_lt _ regev_q_positive

/-- `ChannelMemberKeys::deterministic(channel_id)`: `TEST_ACTIVE_MEMBERS` slots,
each leaf built from the channel-derived Falcon/BabyBear/Regev material, in slot
order; the remaining `MemberTree` slots stay empty (pad-to-MAX). -/
def channelMemberKeysDeterministic (d : Deps) (channelId : Nat) : Res ChannelMemberKeys := do
  let falconKeys ← deterministicMemberFalconKeys channelId testActiveMembers
  let babySeed : Nat → Nat := fun slot => (channelId * 0x9e3779b9 + slot * 256 + 0xb1) % 2 ^ 64
  let regevOf : Nat → RegevPk := fun slot => deterministicRegevPk ((channelId * 31 + slot + 1) % channelIdLimit)
  let slots := indices testActiveMembers
  let leaves := slots.map (fun slot =>
    { pkG := d.falconPkG (FalconKey.fromSeed (falconSeed channelId slot)),
      pkB := d.reduceToHashOut (d.babyPkFromSeed (babySeed slot)),
      regevDigest := d.regevDigest (regevOf slot) : MemberLeaf })
  pure { falconKeys := falconKeys,
         babyKeys := slots.map babySeed,
         regevPks := slots.map regevOf,
         memberTree := leaves }

theorem deterministic_member_keys_have_test_active_members_slots (d : Deps) (channelId : Nat) :
    (channelMemberKeysDeterministic d channelId).toOption.map (fun k => k.memberTree.length)
      = some testActiveMembers := by
  simp [channelMemberKeysDeterministic, deterministicMemberFalconKeys, testActiveMembers,
    slotSeedLimit, Except.toOption, bind, Except.bind, pure, Except.pure, indices_length]

/-- Every fixture member leaf is a function of the PUBLIC channel id and the slot
index alone: knowing `channel_id` reproduces the whole registered member set,
and (with `deterministic_member_falcon_keys`) the matching signing seeds. -/
theorem deterministic_member_set_is_determined_by_the_channel_id
    (d : Deps) (channelId : Nat) (k k' : ChannelMemberKeys)
    (first : channelMemberKeysDeterministic d channelId = .ok k)
    (second : channelMemberKeysDeterministic d channelId = .ok k') :
    k.memberTree = k'.memberTree ∧ k.falconKeys = k'.falconKeys := by
  rw [first] at second
  cases second
  exact ⟨rfl, rfl⟩

/-- `to_reg_record_split`: the `active = member_count + delegate_count` prefix of
the member tree is copied into the record; `bp_member_slot` is pinned to 0; the
recipient is the deterministic test address. `active > MAX_SIG_CLUSTER` is an
`assert!` (a panic). -/
def toRegRecordSplit (keys : ChannelMemberKeys) (channelId memberCount delegateCount : Nat) :
    Res ChannelRegRecord :=
  let active := memberCount + delegateCount
  if active ≤ maxSigCluster then
    let entryAt : Nat → MemberRegEntry := fun i =>
      if i < active then
        let leaf := keys.memberTree.getD i emptyMemberLeaf
        { pkG := leaf.pkG, pkB := leaf.pkB, regevDigest := leaf.regevDigest,
          recipient := testRecipientLimb channelId i }
      else defaultMemberRegEntry
    if channelId = 0 ∨ channelIdLimit ≤ channelId then
      .error (panicWith .channelIdExpect)
    else
      .ok { channelId := channelId, bpMemberSlot := 0, memberCount := memberCount,
            delegateCount := delegateCount,
            members := (indices maxSigCluster).map entryAt }
  else .error (panicWith .regRecordCapacityExceeded)

def toRegRecord (keys : ChannelMemberKeys) (channelId : Nat) : Res ChannelRegRecord :=
  toRegRecordSplit keys channelId testActiveMembers 0

theorem reg_record_has_max_sig_cluster_slots
    (keys : ChannelMemberKeys) (channelId memberCount delegateCount : Nat)
    (record : ChannelRegRecord)
    (built : toRegRecordSplit keys channelId memberCount delegateCount = .ok record) :
    record.members.length = maxSigCluster := by
  simp only [toRegRecordSplit] at built
  split at built
  · split at built
    · cases built
    · cases built; simp [indices_length]
  · cases built

theorem reg_record_pins_block_proposer_slot_zero
    (keys : ChannelMemberKeys) (channelId memberCount delegateCount : Nat)
    (record : ChannelRegRecord)
    (built : toRegRecordSplit keys channelId memberCount delegateCount = .ok record) :
    record.bpMemberSlot = 0 ∧ record.memberCount = memberCount ∧
      record.delegateCount = delegateCount ∧ record.channelId = channelId := by
  simp only [toRegRecordSplit] at built
  split at built
  · split at built
    · cases built
    · cases built; exact ⟨rfl, rfl, rfl, rfl⟩
  · cases built

theorem to_reg_record_uses_zero_delegates (keys : ChannelMemberKeys) (channelId : Nat) :
    toRegRecord keys channelId = toRegRecordSplit keys channelId testActiveMembers 0 := rfl

/-! ## `BlockWitnessGenerator` state -/

structure BlockGen where
  supportedUserCounts : List Nat
  blockNumber : Nat
  channelTree : List (Nat × ChannelLeaf)
  sendLeaves : List (Nat × List SendLeaf)
  depositTree : List Deposit
  publicStateTree : List PublicState
  channelMembers : List (Nat × RegisteredPublic)
  /-- Fixture-only local Falcon signers; production registration never fills it. -/
  localTestSigners : List (Nat × List FalconKey)
  fixtureChannelKeys : List (Nat × ChannelMemberKeys)
  blockHashChain : Hash
  depositHashChain : Hash
  channelRegHashChain : Hash
  blocks : List Block
  deposits : List (Nat × List Deposit)
  depositCounts : Nat
  channelRegistrations : List (ChannelRegRecord × RegisteredPublic)
  blockChainWitness : List (Nat × BlockWitness)
  bpSigEvents : List BpSigEvent
  nextImsbStateCommitmentRoot : Option Hash
  nextChannelCosign : Option CosignBundle
  unsignedStaging : Bool
  deriving DecidableEq, Repr

def genesisBlock : Block := ⟨0, 0, 0, [], 0, 0, 0⟩

/-- `BlockWitnessGenerator::new` — `blocks` starts with ONE genesis placeholder. -/
def newBlockGen (counts : List Nat) : BlockGen :=
  { supportedUserCounts := counts, blockNumber := 0, channelTree := [], sendLeaves := [],
    depositTree := [], publicStateTree := [], channelMembers := [], localTestSigners := [],
    fixtureChannelKeys := [], blockHashChain := 0, depositHashChain := 0,
    channelRegHashChain := 0, blocks := [genesisBlock], deposits := [], depositCounts := 0,
    channelRegistrations := [], blockChainWitness := [], bpSigEvents := [],
    nextImsbStateCommitmentRoot := none, nextChannelCosign := none, unsignedStaging := false }

theorem new_generator_is_empty_with_one_genesis_block (counts : List Nat) :
    (newBlockGen counts).blockNumber = 0 ∧ (newBlockGen counts).blocks = [genesisBlock] ∧
      (newBlockGen counts).bpSigEvents = [] ∧ (newBlockGen counts).localTestSigners = [] ∧
      (newBlockGen counts).unsignedStaging = false ∧
      (newBlockGen counts).nextChannelCosign = none :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

def channelLeafAt (g : BlockGen) (channel : Nat) : ChannelLeaf :=
  (mapGet? g.channelTree channel).getD defaultChannelLeaf

def sendLeavesAt (g : BlockGen) (channel : Nat) : List SendLeaf :=
  (mapGet? g.sendLeaves channel).getD []

/-- `holds_local_signing_keys` — the production-boundary introspection. -/
def holdsLocalSigningKeys (g : BlockGen) (channel : Nat) : Bool :=
  mapContains g.localTestSigners channel

/-- `current_bp_sig_chain` — the running aggregate-list commitment. A value, not
evidence that any signature verified. -/
def currentBpSigChain (d : Deps) (g : BlockGen) : Hash :=
  d.aggListCommitment (g.bpSigEvents.map (fun e => (e.digest, e.signerPks)))

def currentPublicState (d : Deps) (g : BlockGen) : PublicState :=
  { blockNumber := g.blockNumber,
    timestamp := (g.blocks.getLast? |>.map (fun b => b.timestamp)).getD 0,
    accountTreeRoot := d.channelTreeRoot g.channelTree,
    depositTreeRoot := d.depositTreeRoot g.depositTree,
    prevPublicStateRoot := d.publicStateRoot g.publicStateTree }

def currentExtendedPublicState (d : Deps) (g : BlockGen) : ExtPublicState :=
  { inner := currentPublicState d g, blockHashChain := g.blockHashChain,
    depositHashChain := g.depositHashChain, depositCount := g.depositTree.length,
    channelRegHashChain := g.channelRegHashChain, bpSigChain := currentBpSigChain d g }

/-- `public_state::get_num_users` — the first supported width that fits. -/
def getNumUsers (len : Nat) (supported : List Nat) : Option Nat :=
  supported.find? (fun n => len ≤ n)

/-- The `ok_or(TooManyKeyIds)` wrapper around `get_num_users`. -/
def resolveNumUsers (len : Nat) (supported : List Nat) : Res Nat :=
  match getNumUsers len supported with
  | none => .error (.tooManyKeyIds len)
  | some n => .ok n

theorem num_users_is_at_least_the_key_id_count (len : Nat) (supported : List Nat) (n : Nat)
    (found : getNumUsers len supported = some n) : len ≤ n := by
  have mem := List.find?_some found
  simpa using mem

/-- `BlockNumber::add(1)` — errors on the U63 bound. -/
def succBlockNumber (n : Nat) : Res Nat :=
  if n + 1 < blockNumberLimit then .ok (n + 1) else .error .blockNumberError

theorem succ_block_number_increments (n m : Nat) (ok : succBlockNumber n = .ok m) : m = n + 1 := by
  simp only [succBlockNumber] at ok
  split at ok
  · cases ok; rfl
  · cases ok

/-- `ChannelId::new` — rejects `0` (reserved for the dummy channel) and anything
above `u32`. -/
def mkChannelId (value : Nat) : Res Nat :=
  if value = 0 ∨ channelIdLimit ≤ value then .error .channelIdError else .ok value

theorem channel_id_zero_is_rejected : mkChannelId 0 = .error .channelIdError := by
  simp [mkChannelId]

/-- `Block::new` — refuses `key_ids.len() > num_users`, then zero-pads. -/
def mkBlock (numUsers channelId : Nat) (keyIds : List Nat) (timestamp : Nat)
    (txTreeRoot depositChain regChain : Hash) : Res Block :=
  if numUsers < keyIds.length then .error .blockError
  else .ok { numUsers := numUsers, channelId := channelId, timestamp := timestamp,
             keyIds := keyIds ++ List.replicate (numUsers - keyIds.length) 0,
             txTreeRoot := txTreeRoot, depositHashChain := depositChain,
             channelRegHashChain := regChain }

theorem block_key_ids_are_padded_to_num_users
    (numUsers channelId : Nat) (keyIds : List Nat) (timestamp : Nat)
    (txTreeRoot depositChain regChain : Hash) (block : Block)
    (built : mkBlock numUsers channelId keyIds timestamp txTreeRoot depositChain regChain
      = .ok block) : block.keyIds.length = numUsers := by
  simp only [mkBlock] at built
  split at built
  · cases built
  · cases built
    rename_i wide
    simp
    omega

theorem block_copies_the_supplied_chains
    (numUsers channelId : Nat) (keyIds : List Nat) (timestamp : Nat)
    (txTreeRoot depositChain regChain : Hash) (block : Block)
    (built : mkBlock numUsers channelId keyIds timestamp txTreeRoot depositChain regChain
      = .ok block) :
    block.depositHashChain = depositChain ∧ block.channelRegHashChain = regChain ∧
      block.txTreeRoot = txTreeRoot ∧ block.channelId = channelId := by
  simp only [mkBlock] at built
  split at built
  · cases built
  · cases built; exact ⟨rfl, rfl, rfl, rfl⟩

/-! ### Registration admission

`RegisteredChannelPublicData::from_record_and_regev_pks`, in source order:
`record.validate()`, then `delegate_count == 0`, then the Regev key-count match,
then a per-slot Regev digest match — and only then is a member tree built. -/

def regevDigestsMatch (d : Deps) (entries : List MemberRegEntry) (pks : List RegevPk) : Bool :=
  (entries.zip pks).all (fun p => d.regevDigest p.2 == p.1.regevDigest)

def fromRecordAndRegevPks (d : Deps) (record : ChannelRegRecord) (regevPks : List RegevPk) :
    Res RegisteredPublic := do
  let _ ← check (d.validateRecord record) (refuse .recordInvalid)
  let _ ← check (record.delegateCount == 0) (refuse .delegatesPresent)
  let _ ← check (regevPks.length == record.memberCount) (refuse .regevCountMismatch)
  let taken := (record.members.zip regevPks).take record.memberCount
  let _ ← check (taken.all (fun p => d.regevDigest p.2 == p.1.regevDigest))
    (refuse .regevDigestMismatch)
  pure { regevPks := regevPks,
         memberTree := taken.map (fun p =>
           { pkG := d.reduceToHashOut p.1.pkG, pkB := d.reduceToHashOut p.1.pkB,
             regevDigest := d.reduceToHashOut p.1.regevDigest }),
         memberCount := record.memberCount }

theorem record_validation_precedes_every_other_registration_check
    (d : Deps) (record : ChannelRegRecord) (regevPks : List RegevPk)
    (invalid : d.validateRecord record = false) :
    fromRecordAndRegevPks d record regevPks = .error (refuse .recordInvalid) := by
  simp [fromRecordAndRegevPks, check, invalid, bind, Except.bind]

theorem delegates_are_refused_before_the_regev_count_check
    (d : Deps) (record : ChannelRegRecord) (regevPks : List RegevPk)
    (valid : d.validateRecord record = true) (delegates : record.delegateCount ≠ 0) :
    fromRecordAndRegevPks d record regevPks = .error (refuse .delegatesPresent) := by
  simp [fromRecordAndRegevPks, check, valid, delegates, bind, Except.bind]

theorem registration_admission_requires_all_four_checks
    (d : Deps) (record : ChannelRegRecord) (regevPks : List RegevPk) (public : RegisteredPublic)
    (accepted : fromRecordAndRegevPks d record regevPks = .ok public) :
    d.validateRecord record = true ∧ record.delegateCount = 0 ∧
      regevPks.length = record.memberCount ∧ public.memberCount = record.memberCount := by
  simp only [fromRecordAndRegevPks, bind_ok_iff, exists_unit, check_ok_iff, pure_ok_iff,
    beq_iff_eq] at accepted
  obtain ⟨validated, accepted⟩ := accepted
  obtain ⟨delegates, accepted⟩ := accepted
  obtain ⟨counts, accepted⟩ := accepted
  obtain ⟨_, accepted⟩ := accepted
  refine ⟨validated, delegates, counts, ?_⟩
  rw [← accepted]

/-- Every registered member leaf is the `reduce_to_hash_out` of the record entry
at the same slot: the member tree is DERIVED from the record, never supplied. -/
theorem member_tree_is_derived_from_the_record
    (d : Deps) (record : ChannelRegRecord) (regevPks : List RegevPk) (public : RegisteredPublic)
    (accepted : fromRecordAndRegevPks d record regevPks = .ok public) :
    public.memberTree = ((record.members.zip regevPks).take record.memberCount).map
      (fun p => { pkG := d.reduceToHashOut p.1.pkG, pkB := d.reduceToHashOut p.1.pkB,
                  regevDigest := d.reduceToHashOut p.1.regevDigest }) := by
  simp only [fromRecordAndRegevPks, bind_ok_iff, exists_unit, check_ok_iff, pure_ok_iff] at accepted
  obtain ⟨_, accepted⟩ := accepted
  obtain ⟨_, accepted⟩ := accepted
  obtain ⟨_, accepted⟩ := accepted
  obtain ⟨_, accepted⟩ := accepted
  rw [← accepted]

/-- `add_channel_registration_material`: the duplicate/queued check runs FIRST,
before the record is even validated; the fixture signer count is checked LAST,
after the public data is admitted. -/
def addChannelRegistrationMaterial (d : Deps) (g : BlockGen) (record : ChannelRegRecord)
    (regevPks : List RegevPk) (localSigners : Option (List FalconKey)) : Res BlockGen := do
  let channel := record.channelId
  let _ ← check (!(mapContains g.channelMembers channel ||
      g.channelRegistrations.any (fun p => p.1.channelId == channel)))
    (refuse .alreadyRegisteredOrQueued)
  let public ← fromRecordAndRegevPks d record regevPks
  match localSigners with
  | some signers =>
      let _ ← check (signers.length == public.memberCount) (refuse .fixtureSignerCountMismatch)
      pure { g with
             localTestSigners := mapInsert g.localTestSigners channel signers,
             channelRegistrations := g.channelRegistrations ++ [(record, public)],
             channelMembers := mapInsert g.channelMembers channel public }
  | none =>
      pure { g with
             channelRegistrations := g.channelRegistrations ++ [(record, public)],
             channelMembers := mapInsert g.channelMembers channel public }

/-- `add_channel_registration_public` — the keyless production entry point. -/
def addChannelRegistrationPublic (d : Deps) (g : BlockGen) (record : ChannelRegRecord)
    (regevPks : List RegevPk) : Res BlockGen :=
  addChannelRegistrationMaterial d g record regevPks none

theorem duplicate_registration_is_refused_before_record_validation
    (d : Deps) (g : BlockGen) (record : ChannelRegRecord) (regevPks : List RegevPk)
    (signers : Option (List FalconKey))
    (present : mapContains g.channelMembers record.channelId = true) :
    addChannelRegistrationMaterial d g record regevPks signers
      = .error (refuse .alreadyRegisteredOrQueued) := by
  simp [addChannelRegistrationMaterial, check, present, bind, Except.bind]

/-- The production registration path retains no signing key for the channel. -/
theorem public_registration_holds_no_signing_key
    (d : Deps) (g : BlockGen) (record : ChannelRegRecord) (regevPks : List RegevPk)
    (g' : BlockGen) (accepted : addChannelRegistrationPublic d g record regevPks = .ok g') :
    g'.localTestSigners = g.localTestSigners := by
  simp only [addChannelRegistrationPublic, addChannelRegistrationMaterial, bind_ok_iff,
    exists_unit, check_ok_iff, pure_ok_iff] at accepted
  obtain ⟨_, accepted⟩ := accepted
  obtain ⟨_, _, accepted⟩ := accepted
  rw [← accepted]

/-- A registration is queued AND mirrored into `channel_members` in one step; the
channel-tree leaf is NOT written yet (the registration block writes it). -/
theorem registration_is_queued_and_mirrored_without_touching_the_channel_tree
    (d : Deps) (g : BlockGen) (record : ChannelRegRecord) (regevPks : List RegevPk)
    (g' : BlockGen) (accepted : addChannelRegistrationPublic d g record regevPks = .ok g') :
    g'.channelTree = g.channelTree ∧
      mapContains g'.channelMembers record.channelId = true ∧
      g'.channelRegistrations.length = g.channelRegistrations.length + 1 := by
  simp only [addChannelRegistrationPublic, addChannelRegistrationMaterial, bind_ok_iff,
    exists_unit, check_ok_iff, pure_ok_iff] at accepted
  obtain ⟨_, accepted⟩ := accepted
  obtain ⟨public, _, accepted⟩ := accepted
  subst accepted
  exact ⟨rfl, map_contains_of_insert _ _ _, by simp⟩

/-- `add_channel_registration(channel_id)` — the FIXTURE path: it derives every
member's Falcon key from the public channel id and RETAINS them as local signers. -/
def addChannelRegistrationFixture (d : Deps) (g : BlockGen) (channelId : Nat) :
    Res (BlockGen × ChannelMemberKeys) := do
  let keys ← channelMemberKeysDeterministic d channelId
  let record ← toRegRecord keys channelId
  let g' ← addChannelRegistrationMaterial d g record keys.regevPks (some keys.falconKeys)
  pure ({ g' with fixtureChannelKeys := mapInsert g'.fixtureChannelKeys channelId keys }, keys)

/-- The consequence the header names: a channel registered through the fixture
path leaves the generator holding every member's signing key, and those keys are
the channel-id-derived ones. -/
theorem fixture_registration_retains_every_member_signing_key
    (d : Deps) (g : BlockGen) (channelId : Nat) (g' : BlockGen) (keys : ChannelMemberKeys)
    (accepted : addChannelRegistrationFixture d g channelId = .ok (g', keys)) :
    mapGet? g'.localTestSigners channelId = some keys.falconKeys ∧
      holdsLocalSigningKeys g' channelId = true := by
  simp only [addChannelRegistrationFixture, addChannelRegistrationMaterial, bind_ok_iff,
    exists_unit, check_ok_iff, pure_ok_iff, Prod.mk.injEq] at accepted
  obtain ⟨k, _, accepted⟩ := accepted
  obtain ⟨record, recordOk, accepted⟩ := accepted
  obtain ⟨st, inner, stateEq, keysEq⟩ := accepted
  obtain ⟨_, public, _, _, materialEq⟩ := inner
  have channelEq : record.channelId = channelId :=
    (reg_record_pins_block_proposer_slot_zero k channelId testActiveMembers 0 record recordOk).2.2.2
  subst keysEq
  subst materialEq
  subst stateEq
  refine ⟨?_, ?_⟩
  · simp only [channelEq]
    exact map_get_insert_self _ _ _
  · simp only [holdsLocalSigningKeys, mapContains, channelEq, map_get_insert_self]
    rfl


/-! ### Registration block

`add_registration_block` drains ONE queued registration, proves against the
still-unregistered channel tree, then writes the channel leaf. -/

/-- `ChannelMerkleProof::dummy` / `SendMerkleProof::dummy`. -/
def dummyProof : Hash := 0

/-- The all-zero `RegevPk` the padding slots carry. -/
def dummyRegevPk : RegevPk := ⟨List.replicate regevN 0, List.replicate regevN 0⟩

def paddingWitness (numUsers : Nat) : List ChannelLeaf × List Hash × List Hash × List RegevPk :=
  ((indices numUsers).map (fun _ => defaultChannelLeaf),
   (indices numUsers).map (fun _ => dummyProof),
   (indices numUsers).map (fun _ => dummyProof),
   (indices numUsers).map (fun _ => dummyRegevPk))

def addRegistrationBlock (d : Deps) (g : BlockGen) (timestamp : Nat) : Res (BlockGen × Nat) :=
  match g.channelRegistrations with
  | [] => .error (refuse .noQueuedRegistration)
  | (record, public) :: queued => do
      let channel := record.channelId
      let _ ← check (channelLeafAt g channel == defaultChannelLeaf) (refuse .channelAlreadyOnChain)
      let newBlockNumber ← succBlockNumber g.blockNumber
      let _ ← check (!mapContains g.deposits newBlockNumber)
        (refuse .registrationBlockCarriesDeposits)
      let numUsers ← resolveNumUsers 0 g.supportedUserCounts
      let newRegChain := d.hashRecordWithPrev record g.channelRegHashChain
      let block ← mkBlock numUsers 0 [] timestamp 0 g.depositHashChain newRegChain
      let prevExt := currentExtendedPublicState d g
      let publicStateMerkleProof := d.publicStateProof g.publicStateTree g.blockNumber
      let channelMerkleProof := d.channelProof g.channelTree channel
      let registeredLeaf : ChannelLeaf :=
        { index := 0, prev := 0, sendTreeRoot := defaultChannelLeaf.sendTreeRoot,
          memberRoot := d.memberRoot public.memberTree }
      let padding := paddingWitness numUsers
      let witness : BlockWitness :=
        { depositStepWitness := [], channelRegStepWitness := [(record, channelMerkleProof)],
          block := block, prevAccountLeaves := padding.1, userMerkleProofs := padding.2.1,
          sendMerkleProofs := padding.2.2.1, publicStateMerkleProof := publicStateMerkleProof,
          memberLeaves := none, newMemberLeaves := none, signerCount := none,
          memberRegevPks := some padding.2.2.2, channelStateFields := none,
          txV2Indices := none, txV2s := none, txV2MerkleProofs := none,
          channelActionIndices := none, channelActions := none,
          channelActionMerkleProofs := none }
      pure ({ g with
              publicStateTree := g.publicStateTree ++ [prevExt.inner],
              channelTree := mapInsert g.channelTree channel registeredLeaf,
              channelRegistrations := queued,
              blockChainWitness := mapInsert g.blockChainWitness newBlockNumber witness,
              channelRegHashChain := newRegChain,
              blockHashChain := d.hashBlockWithPrev block g.blockHashChain,
              blocks := g.blocks ++ [block],
              blockNumber := newBlockNumber }, channel)

theorem registration_block_requires_a_queued_registration
    (d : Deps) (g : BlockGen) (timestamp : Nat) (empty : g.channelRegistrations = []) :
    addRegistrationBlock d g timestamp = .error (refuse .noQueuedRegistration) := by
  simp [addRegistrationBlock, empty]

theorem registration_is_one_time_per_channel
    (d : Deps) (g : BlockGen) (timestamp : Nat) (record : ChannelRegRecord)
    (public : RegisteredPublic) (queued : List (ChannelRegRecord × RegisteredPublic))
    (front : g.channelRegistrations = (record, public) :: queued)
    (onChain : channelLeafAt g record.channelId ≠ defaultChannelLeaf) :
    addRegistrationBlock d g timestamp = .error (refuse .channelAlreadyOnChain) := by
  simp [addRegistrationBlock, front, check, onChain, bind, Except.bind]

theorem registration_block_accepts_no_deposits
    (d : Deps) (g : BlockGen) (timestamp : Nat) (record : ChannelRegRecord)
    (public : RegisteredPublic) (queued : List (ChannelRegRecord × RegisteredPublic))
    (front : g.channelRegistrations = (record, public) :: queued)
    (clean : channelLeafAt g record.channelId = defaultChannelLeaf)
    (next : Nat) (advance : succBlockNumber g.blockNumber = .ok next)
    (pending : mapContains g.deposits next = true) :
    addRegistrationBlock d g timestamp = .error (refuse .registrationBlockCarriesDeposits) := by
  simp [addRegistrationBlock, front, check, clean, advance, pending, bind, Except.bind]

theorem registration_block_writes_the_member_root_and_advances_both_chains
    (d : Deps) (g : BlockGen) (timestamp : Nat) (g' : BlockGen) (channel : Nat)
    (accepted : addRegistrationBlock d g timestamp = .ok (g', channel)) :
    ∃ record public queued,
      g.channelRegistrations = (record, public) :: queued ∧
      channel = record.channelId ∧
      g'.channelRegistrations = queued ∧
      g'.channelRegHashChain = d.hashRecordWithPrev record g.channelRegHashChain ∧
      g'.depositHashChain = g.depositHashChain ∧
      g'.blockNumber = g.blockNumber + 1 ∧
      mapGet? g'.channelTree record.channelId =
        some { index := 0, prev := 0, sendTreeRoot := defaultChannelLeaf.sendTreeRoot,
               memberRoot := d.memberRoot public.memberTree } := by
  simp only [addRegistrationBlock] at accepted
  split at accepted
  · cases accepted
  · rename_i record public queued front
    refine ⟨record, public, queued, front, ?_⟩
    simp only [bind_ok_iff, exists_unit, check_ok_iff, pure_ok_iff, Prod.mk.injEq] at accepted
    obtain ⟨_, accepted⟩ := accepted
    obtain ⟨next, advance, accepted⟩ := accepted
    obtain ⟨_, accepted⟩ := accepted
    obtain ⟨numUsers, _, accepted⟩ := accepted
    obtain ⟨block, _, stateEq, channelEq⟩ := accepted
    subst channelEq
    subst stateEq
    have step := succ_block_number_increments _ _ advance
    subst step
    exact ⟨rfl, rfl, rfl, rfl, rfl, map_get_insert_self _ _ _⟩

/-- A registration block transitions no channel leaf, so it carries no member set
and no signature statement: the N-of-N binding is gated on a block that signs. -/
theorem registration_block_carries_no_member_set_and_no_signature
    (d : Deps) (g : BlockGen) (timestamp : Nat) (g' : BlockGen) (channel : Nat)
    (accepted : addRegistrationBlock d g timestamp = .ok (g', channel)) :
    g'.bpSigEvents = g.bpSigEvents ∧
      ∀ w, mapGet? g'.blockChainWitness g'.blockNumber = some w →
        w.memberLeaves = none ∧ w.signerCount = none ∧ w.channelStateFields = none ∧
          w.txV2s = none ∧ w.channelActions = none := by
  simp only [addRegistrationBlock] at accepted
  split at accepted
  · cases accepted
  · simp only [bind_ok_iff, exists_unit, check_ok_iff, pure_ok_iff, Prod.mk.injEq] at accepted
    obtain ⟨_, accepted⟩ := accepted
    obtain ⟨next, advance, accepted⟩ := accepted
    obtain ⟨_, accepted⟩ := accepted
    obtain ⟨numUsers, _, accepted⟩ := accepted
    obtain ⟨block, _, stateEq, _⟩ := accepted
    subst stateEq
    refine ⟨rfl, ?_⟩
    intro w stored
    rw [map_get_insert_self] at stored
    cases stored
    exact ⟨rfl, rfl, rfl, rfl, rfl⟩

/-! ### Deposit queueing -/

def addDeposit (g : BlockGen) (depositor : Nat) (recipient : Hash)
    (tokenIndex amount : Nat) (auxData : Hash) : Res BlockGen := do
  let target ← succBlockNumber g.blockNumber
  let deposit : Deposit :=
    { depositIndex := g.depositCounts, depositor := depositor, recipient := recipient,
      tokenIndex := tokenIndex, amount := amount, blockNumber := target, auxData := auxData }
  pure { g with
         deposits := mapInsert g.deposits target ((mapGet? g.deposits target).getD [] ++ [deposit]),
         depositCounts := g.depositCounts + 1 }

/-- The deposit index is the pre-call counter and the counter increments by one;
the deposit is queued for the NEXT block, not the current one. -/
theorem queued_deposit_takes_the_next_index_and_next_block
    (g : BlockGen) (depositor : Nat) (recipient : Hash) (tokenIndex amount : Nat)
    (auxData : Hash) (g' : BlockGen)
    (accepted : addDeposit g depositor recipient tokenIndex amount auxData = .ok g') :
    g'.depositCounts = g.depositCounts + 1 ∧
      mapGet? g'.deposits (g.blockNumber + 1) =
        some ((mapGet? g.deposits (g.blockNumber + 1)).getD [] ++
          [{ depositIndex := g.depositCounts, depositor := depositor, recipient := recipient,
             tokenIndex := tokenIndex, amount := amount, blockNumber := g.blockNumber + 1,
             auxData := auxData }]) ∧
      g'.depositTree = g.depositTree := by
  simp only [addDeposit, bind_ok_iff, pure_ok_iff] at accepted
  obtain ⟨target, advance, stateEq⟩ := accepted
  have step := succ_block_number_increments _ _ advance
  subst step
  subst stateEq
  exact ⟨rfl, map_get_insert_self _ _ _, rfl⟩

/-! ### The block path -/

/-- `update_channel_tree::channel_leaf_member_root` as it stands on this branch
(src lines 163-170): the IDENTITY on `prev_member_pubkeys_root`. Pinned body —
see the `pinned-callee-body` boundary. -/
def channelLeafMemberRoot (_tx : TxV2) (_action : Option ChannelAction)
    (_newLeaves : List MemberLeaf) (prevRoot : Hash) : Hash := prevRoot

theorem channel_leaf_member_root_is_the_identity
    (tx : TxV2) (action : Option ChannelAction) (leaves : List MemberLeaf) (prev : Hash) :
    channelLeafMemberRoot tx action leaves prev = prev := rfl

/-- `advance_registered_member_set`. Its guard in `add_block_with_tx_v2_inner` is
`member_pubkeys_root != prev.member_pubkeys_root`, which
`channel_leaf_member_root_is_the_identity` makes identically false — so on this
branch the block path never calls it. -/
def advanceRegisteredMemberSet (d : Deps) (g : BlockGen) (channel : Nat)
    (newLeaves : List MemberLeaf) : Res BlockGen := do
  let _ ← check (newLeaves.length == maxSigCluster) (refuse .memberLeavesWrongLength)
  match mapGet? g.channelMembers channel with
  | none => .error (refuse .channelNotRegisteredForAdvance)
  | some public =>
      let count := (newLeaves.filter (fun l => l != emptyMemberLeaf)).length
      let updated : RegisteredPublic :=
        { public with memberTree := newLeaves, memberCount := count }
      let leavesMatch :=
        match mapGet? g.localTestSigners channel with
        | none => true
        | some signers =>
            signers.length == count &&
              (signers.zip newLeaves).all (fun p => d.reduceToHashOut (d.falconPkG p.1) == p.2.pkG)
      pure { g with
             channelMembers := mapInsert g.channelMembers channel updated,
             localTestSigners :=
               if leavesMatch then g.localTestSigners else mapErase g.localTestSigners channel }

theorem member_set_advance_requires_all_slots
    (d : Deps) (g : BlockGen) (channel : Nat) (newLeaves : List MemberLeaf)
    (wrong : newLeaves.length ≠ maxSigCluster) :
    advanceRegisteredMemberSet d g channel newLeaves = .error (refuse .memberLeavesWrongLength) := by
  simp [advanceRegisteredMemberSet, check, wrong, bind, Except.bind]

/-- Fail-closed: a member set the harness's per-slot keys no longer match drops
those keys rather than leaving a stale signer list behind. -/
theorem member_set_advance_drops_mismatched_fixture_signers
    (d : Deps) (g : BlockGen) (channel : Nat) (newLeaves : List MemberLeaf)
    (public : RegisteredPublic) (signers : List FalconKey) (g' : BlockGen)
    (registered : mapGet? g.channelMembers channel = some public)
    (held : mapGet? g.localTestSigners channel = some signers)
    (mismatch : ¬ (signers.length = (newLeaves.filter (fun l => l != emptyMemberLeaf)).length ∧
      (signers.zip newLeaves).all (fun p => d.reduceToHashOut (d.falconPkG p.1) == p.2.pkG) = true))
    (accepted : advanceRegisteredMemberSet d g channel newLeaves = .ok g') :
    holdsLocalSigningKeys g' channel = false := by
  simp only [advanceRegisteredMemberSet, bind_ok_iff, exists_unit, check_ok_iff,
    registered, held, pure_ok_iff] at accepted
  obtain ⟨_, stateEq⟩ := accepted
  subst stateEq
  have notMatch :
      ((signers.length == (newLeaves.filter (fun l => l != emptyMemberLeaf)).length) &&
        (signers.zip newLeaves).all
          (fun p => d.reduceToHashOut (d.falconPkG p.1) == p.2.pkG)) = false := by
    rcases hl : (signers.length == (newLeaves.filter (fun l => l != emptyMemberLeaf)).length)
      with _ | _
    · simp [hl]
    · rcases hr : (signers.zip newLeaves).all
        (fun p => d.reduceToHashOut (d.falconPkG p.1) == p.2.pkG) with _ | _
      · simp [hl, hr]
      · exact absurd ⟨eq_of_beq hl, hr⟩ mismatch
  simp only [holdsLocalSigningKeys, mapContains, notMatch, Bool.false_eq_true, if_neg,
    not_false_eq_true, map_get_erase_self, Option.isSome_none]



/-! ### TxV2 witness shape admission (`add_block_with_tx_v2_inner`, first block) -/

structure BlockArgs where
  channelId : Nat
  keyIds : List Nat
  timestamp : Nat
  txTreeRoot : Hash
  txV2 : Option BlockTxV2Witness
  deriving DecidableEq, Repr

/-- A slot carries a `TxClass::ChannelAction` iff its key id is non-padding AND
its TxV2 says so. `key_ids` is the UNPADDED prefix; slots beyond it are padding. -/
def hasChannelActionSlot (w : BlockTxV2Witness) (keyIds : List Nat) : Bool :=
  (w.txV2s.zip keyIds).any (fun p => p.2 != 0 && p.1.txClass == TxClass.channelAction)

def actionLens (w : BlockTxV2Witness) : Option Nat × Option Nat × Option Nat :=
  (w.channelActionIndices.map List.length, w.channelActions.map List.length,
   w.channelActionMerkleProofs.map List.length)

/-- Array-length check first, then the M-2 channel-action sub-witness rules. -/
def checkTxV2Witness (numUsers : Nat) (keyIds : List Nat) (w : BlockTxV2Witness) : Res Unit :=
  if w.txV2Indices.length ≠ numUsers ∨ w.txV2s.length ≠ numUsers ∨
      w.txV2MerkleProofs.length ≠ numUsers then
    .error (refuse .txV2ArrayLength)
  else
    let full := (some numUsers, some numUsers, some numUsers)
    if hasChannelActionSlot w keyIds ∧ actionLens w ≠ full then
      .error (refuse .channelActionSubwitnessMissing)
    else if ¬ hasChannelActionSlot w keyIds ∧ actionLens w ≠ (none, none, none) ∧
        actionLens w ≠ full then
      .error (refuse .channelActionSubwitnessShape)
    else .ok ()

/-- M-2: a `TxClass::ChannelAction` slot whose sub-witness is missing is refused
at witness construction, not thousands of constraints deep in proving. -/
theorem channel_action_slot_without_its_subwitness_is_refused
    (numUsers : Nat) (keyIds : List Nat) (w : BlockTxV2Witness)
    (sized : ¬ (w.txV2Indices.length ≠ numUsers ∨ w.txV2s.length ≠ numUsers ∨
      w.txV2MerkleProofs.length ≠ numUsers))
    (action : hasChannelActionSlot w keyIds = true)
    (missing : w.channelActions = none) :
    checkTxV2Witness numUsers keyIds w = .error (refuse .channelActionSubwitnessMissing) := by
  have lens : actionLens w ≠ (some numUsers, some numUsers, some numUsers) := by
    simp [actionLens, missing]
  simp [checkTxV2Witness, sized, action, lens]

theorem tx_v2_array_length_is_checked_first
    (numUsers : Nat) (keyIds : List Nat) (w : BlockTxV2Witness)
    (wrong : w.txV2s.length ≠ numUsers) :
    checkTxV2Witness numUsers keyIds w = .error (refuse .txV2ArrayLength) := by
  simp [checkTxV2Witness, wrong]

theorem accepted_tx_v2_witness_is_sized_to_num_users
    (numUsers : Nat) (keyIds : List Nat) (w : BlockTxV2Witness)
    (accepted : checkTxV2Witness numUsers keyIds w = .ok ()) :
    w.txV2Indices.length = numUsers ∧ w.txV2s.length = numUsers ∧
      w.txV2MerkleProofs.length = numUsers := by
  simp only [checkTxV2Witness] at accepted
  split at accepted
  · cases accepted
  · rename_i sized
    push_neg at sized
    exact sized

/-! ### IMCH message staging and signature collection -/

/-- The Phase-6 co-signed-state branch: `h2_tag == tx_tree_root` is checked
BEFORE the `channel_fund.channel_id == channel_id` hygiene check; only then is
`from_channel_state` used. The `None` branch is the pre-Phase-6 projection. -/
def stageChannelStateFields (d : Deps) (args : BlockArgs) (newBlockNumber : Nat)
    (imsbH1 : Hash) (staged : Option CosignBundle) : Res ChannelStateFields :=
  match staged with
  | some bundle =>
      if bundle.state.h2Tag ≠ args.txTreeRoot then .error (refuse .cosignH2TagMismatch)
      else if bundle.state.fundChannelId ≠ bundle.state.channelId then
        .error (refuse .cosignFundChannelMismatch)
      else .ok (d.fromChannelState bundle.state)
  | none =>
      .ok { defaultChannelStateFields with
            smallBlockNumber := newBlockNumber, balanceStateH1 := imsbH1,
            stateVersion := newBlockNumber }

theorem cosigned_state_must_authorise_this_block
    (d : Deps) (args : BlockArgs) (newBlockNumber : Nat) (imsbH1 : Hash) (bundle : CosignBundle)
    (other : bundle.state.h2Tag ≠ args.txTreeRoot) :
    stageChannelStateFields d args newBlockNumber imsbH1 (some bundle)
      = .error (refuse .cosignH2TagMismatch) := by
  simp [stageChannelStateFields, other]

theorem h2_tag_check_precedes_the_fund_channel_check
    (d : Deps) (args : BlockArgs) (newBlockNumber : Nat) (imsbH1 : Hash) (bundle : CosignBundle)
    (fields : ChannelStateFields)
    (accepted : stageChannelStateFields d args newBlockNumber imsbH1 (some bundle) = .ok fields) :
    bundle.state.h2Tag = args.txTreeRoot ∧
      bundle.state.fundChannelId = bundle.state.channelId ∧
      fields = d.fromChannelState bundle.state := by
  simp only [stageChannelStateFields] at accepted
  split at accepted
  · cases accepted
  · rename_i tagOk
    split at accepted
    · cases accepted
    · rename_i fundOk
      cases accepted
      exact ⟨by simpa using tagOk, by simpa using fundOk, rfl⟩

/-- The projection branch derives `small_block_number` and `state_version` from
the NEW block number and copies the staged `balance_state_h1`; every other limb
is the default. -/
theorem projected_fields_are_derived_from_the_new_block_number
    (d : Deps) (args : BlockArgs) (newBlockNumber : Nat) (imsbH1 : Hash)
    (fields : ChannelStateFields)
    (accepted : stageChannelStateFields d args newBlockNumber imsbH1 none = .ok fields) :
    fields.smallBlockNumber = newBlockNumber ∧ fields.stateVersion = newBlockNumber ∧
      fields.balanceStateH1 = imsbH1 ∧ fields.epoch = 0 ∧ fields.prevDigest = 0 := by
  simp only [stageChannelStateFields] at accepted
  cases accepted
  exact ⟨rfl, rfl, rfl, rfl, rfl⟩

/-- `decode_cosign_blob` + the `pk_g = Poseidon(IMFK||encode(h))` rebinding, slot
by slot. Slot-order is checked BEFORE the blob is decoded, and the decode before
the identity rebinding. -/
def collectCosignatures (d : Deps) (digest : Hash) :
    List MemberSignature → Nat → Res (List Hash × List SigWitness)
  | [], _ => .ok ([], [])
  | entry :: rest, slot =>
      if entry.memberSlot ≠ slot then .error (refuse .cosignSlotOrder)
      else
        match d.decodeCosignBlob entry.signature with
        | none => .error (refuse .cosignBlobDecode)
        | some (sig, h) =>
            if d.falconPkDigest h ≠ entry.pkG then .error (refuse .cosignPkgMismatch)
            else
              (collectCosignatures d digest rest (slot + 1)).map
                (fun p => (entry.pkG :: p.1, ⟨h, digest, sig⟩ :: p.2))

theorem cosignature_slot_order_is_checked_before_the_blob_decode
    (d : Deps) (digest : Hash) (entry : MemberSignature) (rest : List MemberSignature) (slot : Nat)
    (wrongSlot : entry.memberSlot ≠ slot) :
    collectCosignatures d digest (entry :: rest) slot = .error (refuse .cosignSlotOrder) := by
  simp [collectCosignatures, wrongSlot]

/-- Every accepted cosignature's own public polynomial hashes to the pk_g it
claims: a substituted public polynomial is refused. This is a statement about the
`falcon_pk_digest` CALL, not about signature validity. -/
theorem accepted_cosignatures_rebind_the_public_polynomial
    (d : Deps) (digest : Hash) :
    ∀ (entries : List MemberSignature) (slot : Nat) (out : List Hash × List SigWitness),
      collectCosignatures d digest entries slot = .ok out →
        ∀ w ∈ out.2, d.falconPkDigest w.publicPoly ∈ entries.map (fun e => e.pkG) := by
  intro entries
  induction entries with
  | nil =>
      intro slot out accepted w mem
      simp only [collectCosignatures] at accepted
      cases accepted
      simp at mem
  | cons entry rest ih =>
      intro slot out accepted w mem
      simp only [collectCosignatures] at accepted
      split at accepted
      · cases accepted
      · split at accepted
        · cases accepted
        · rename_i sig h _
          split at accepted
          · cases accepted
          · rename_i bound
            simp only [Except.map] at accepted
            split at accepted
            · cases accepted
            · rename_i tail tailOk
              cases accepted
              simp only [List.mem_cons] at mem
              cases mem with
              | inl head =>
                  subst head
                  simp only [List.map_cons, List.mem_cons]
                  exact Or.inl (by simpa using bound)
              | inr rest' =>
                  simp only [List.map_cons, List.mem_cons]
                  exact Or.inr (ih (slot + 1) tail tailOk w rest')

/-- The three signer-collection branches of `add_block_with_tx_v2_inner`. -/
def collectSigners (d : Deps) (public : RegisteredPublic) (digest : Hash)
    (staged : Option CosignBundle) (localSigners : Option (List FalconKey))
    (unsignedStaging : Bool) : Res (List Hash × List SigWitness) :=
  match staged with
  | some bundle =>
      if unsignedStaging then
        .ok ((indices public.memberCount).map
          (fun slot => (public.memberTree.getD slot emptyMemberLeaf).pkG), [])
      else if bundle.signatures.length ≠ public.memberCount then
        .error (refuse .cosignCountMismatch)
      else collectCosignatures d digest bundle.signatures 0
  | none =>
      match localSigners with
      | none => .error (refuse .noCosignaturesAndNoLocalKeys)
      | some keys =>
          .ok (keys.map d.falconPkG,
               keys.map (fun k => ⟨d.falconPkCoefficients k, digest, d.falconSign k digest⟩))

/-- The production boundary: a channel registered through the keyless path with
no staged cosign bundle cannot produce a block at all. -/
theorem public_registration_cannot_sign_a_block
    (d : Deps) (public : RegisteredPublic) (digest : Hash) (unsignedStaging : Bool) :
    collectSigners d public digest none none unsignedStaging
      = .error (refuse .noCosignaturesAndNoLocalKeys) := by
  simp [collectSigners]

/-- N-of-N: fewer cosignatures than registered members is refused (equivalently,
any single member can block production). -/
theorem cosignature_count_must_equal_the_member_count
    (d : Deps) (public : RegisteredPublic) (digest : Hash) (bundle : CosignBundle)
    (local' : Option (List FalconKey))
    (short : bundle.signatures.length ≠ public.memberCount) :
    collectSigners d public digest (some bundle) local' false
      = .error (refuse .cosignCountMismatch) := by
  simp [collectSigners, short]

/-- Exit-kit staging folds the REGISTERED signer set and records NO gadget
witness, so the statement is known before any member signs. -/
theorem unsigned_staging_records_the_registered_set_and_no_witness
    (d : Deps) (public : RegisteredPublic) (digest : Hash) (bundle : CosignBundle)
    (local' : Option (List FalconKey)) :
    collectSigners d public digest (some bundle) local' true
      = .ok ((indices public.memberCount).map
          (fun slot => (public.memberTree.getD slot emptyMemberLeaf).pkG), []) := by
  simp [collectSigners]

/-- The local-signing fallback signs with EVERY held key over the block digest.
The signatures are produced here, natively; nothing verifies them. -/
theorem local_fallback_signs_with_every_held_key
    (d : Deps) (public : RegisteredPublic) (digest : Hash) (keys : List FalconKey)
    (unsignedStaging : Bool) (out : List Hash × List SigWitness)
    (accepted : collectSigners d public digest none (some keys) unsignedStaging = .ok out) :
    out.1 = keys.map d.falconPkG ∧ out.2.length = keys.length ∧
      ∀ w ∈ out.2, w.message = digest := by
  simp only [collectSigners] at accepted
  cases accepted
  refine ⟨rfl, by simp, ?_⟩
  intro w mem
  simp only [List.mem_map] at mem
  obtain ⟨k, _, rfl⟩ := mem
  rfl

/-- `build_agg_sig_list_proof` refuses a span containing a staged unsigned event:
such a generator can anchor an exit kit but never prove a validity span. Modeled
as the refusal PRECONDITION only; the plonky2 recursion is untranslated. -/
def aggSigListProofAdmissible (events : List BpSigEvent) : Res (Option Unit) :=
  if events.isEmpty then .ok none
  else if events.any (fun e => e.witnesses.length != e.signerPks.length) then
    .error (refuse .unsignedEventInSpan)
  else .ok (some ())

theorem an_unsigned_staged_event_can_never_prove_a_validity_span
    (events : List BpSigEvent) (event : BpSigEvent) (present : event ∈ events)
    (unsigned : event.witnesses.length ≠ event.signerPks.length) :
    aggSigListProofAdmissible events = .error (refuse .unsignedEventInSpan) := by
  have nonEmpty : events.isEmpty = false := by
    cases events with
    | nil => simp at present
    | cons _ _ => rfl
  have anyUnsigned : events.any (fun e => e.witnesses.length != e.signerPks.length) = true := by
    refine List.any_eq_true.mpr ⟨event, present, ?_⟩
    simpa using unsigned
  simp [aggSigListProofAdmissible, nonEmpty, anyUnsigned]


end Zkp.Implementation.WitnessGenerators
