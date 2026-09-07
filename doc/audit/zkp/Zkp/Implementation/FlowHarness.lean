import Std

/-!
# FlowHarness: scenario structure of two test-only harness files

Sources:
* src/circuits/channel/e2e_flow.rs (1428 lines) — the channel-layer v2 end-to-end
  flow suite: two happy-path tests plus a 17-test negative suite.
* src/circuits/validity/block_hash_chain/nofn_attack.rs (708 lines) — the
  "PHASE 5" adversarial construction of the design §2.1 attack (one cosigner
  tries to settle a block that pays the whole channel pool to themselves).

Both files are declared `#[cfg(test)] mod` in their `mod.rs` (channel/mod.rs
lines 7-8, block_hash_chain/mod.rs lines 9-10). They contain NO production
code: every executable line is compiled only into the test binary and is
line-mapped as test-only, and NO theorem in this module is linked to any
source span.

What this module IS: a handwritten record of the scenario structure of the two
harnesses — the pinned fixture constants, the steps each harness walks, which
step is expected to be refused, and which PRODUCTION check (file and line
range, as data) the harness attributes each refusal to — together with an
executable restatement of the three signing-slot rules of
`UpdateUserTree::check_signing_slot` (update_channel_tree.rs 277-316) applied
to the harness's three signer-set shapes, so that "A1 breaks the floor, A2
satisfies everything except the root connect, the honest 3-of-3 shape
satisfies all three" is stated over the same data the test asserts.

What this module is NOT: it is not a refinement of the Rust harness, of the
plonky2 circuits, of `BlockHashChainProcessor::prove_block`, of the Falcon
signature stack or of the Regev STARK verifiers, and it does NOT prove that
the §2.1 attack is impossible. The circuit-side refusals (the in-circuit
thermometer/root connect of update_channel_tree.rs 1049-1260, the
`C == final.bp_sig_chain` gate of validity_circuit.rs 242-262, the Falcon norm
bound of `falcon_sig::agg`), the Poseidon member-root recompute, signature
unforgeability, proof soundness and whether the ignored-in-debug tests were
actually executed remain explicit, undischarged boundaries named in the
line maps. The root mismatch that isolates shape A2 is an explicit premise
of the corresponding theorem, mirroring the runtime assertion at
nofn_attack.rs 526-529; it is not derived from any hash property.

The e2e_flow.rs half records: the fixture constants, the five verifier-checked
transitions with the version/H2/chain expectations the happy path asserts, the
structural transport verifier (which accepts exactly the empty envelope and
verifies nothing else), and the negative suite as a list of (test, tampering,
expected error variant) records. The witness verifiers those tests call are
modeled in Zkp.Implementation.ChannelStateUpdate, which is deliberately NOT
imported here: this module records expected outcomes as data and derives
nothing about the verifiers.
-/

namespace Zkp.Implementation.FlowHarness

/-! ## Classification of the two source files -/

/-- How a source file is compiled. Both harness files are `#[cfg(test)]`. -/
inductive SourceRole where
  | production
  | testOnly
  deriving DecidableEq, Repr

def e2eFlowPath : String := "src/circuits/channel/e2e_flow.rs"
def nofnAttackPath : String := "src/circuits/validity/block_hash_chain/nofn_attack.rs"

def e2eFlowRole : SourceRole := .testOnly
def nofnAttackRole : SourceRole := .testOnly

theorem both_harness_files_are_test_only :
    e2eFlowRole = .testOnly ∧ nofnAttackRole = .testOnly := ⟨rfl, rfl⟩

/-- A production check the harness attributes a refusal to, recorded as data:
file, inclusive line range, the design name of the constraint, and the native
error-message fragment the test asserts (empty when the refusal is not
attributed through a native message). -/
structure RefusalSite where
  file : String
  firstLine : Nat
  lastLine : Nat
  constraint : String
  nativeMessage : String
  deriving DecidableEq, Repr

def updateChannelTreePath : String :=
  "src/circuits/validity/block_hash_chain/update_channel_tree.rs"
def validityCircuitPath : String :=
  "src/circuits/validity/block_hash_chain/validity_circuit.rs"
def falconAggPath : String := "src/falcon_sig/agg.rs"

/-! ## nofn_attack.rs: pinned fixture constants (lines 115-124, 207) -/

def attackChannelId : Nat := 1
def member1Funds : Nat := 6
def member2Funds : Nat := 4
/-- The attacker contributed nothing; the theft is the whole pool (line 124). -/
def theft : Nat := member1Funds + member2Funds
def registeredMembers : Nat := 3
def attackerSlot : Nat := 0
/-- `constants::MAX_SIG_CLUSTER` (constants.rs line 135). -/
def maxSigCluster : Nat := 8
/-- Design §5.4 item 2 floor restated at update_channel_tree.rs 277. -/
def signerCountFloor : Nat := 2
def supportedUserCounts : List Nat := [2]
/-- The theft transfer's `aux_data` (line 317): zero, which the harness records
as what disarms both would-be second factors. -/
def theftAuxData : Nat := 0

theorem theft_pinned : theft = 10 := rfl
theorem max_sig_cluster_pinned : maxSigCluster = 8 := rfl
theorem signer_count_floor_pinned : signerCountFloor = 2 := rfl
theorem registered_members_pinned : registeredMembers = 3 := rfl
theorem attacker_funds_nothing : theft = member1Funds + member2Funds := rfl

/-- What the harness grants the attacker (lines 27-29, 222-227): one real
Falcon key, the channel's `prev_private_state`, the ability to mint fresh keys,
and NOT the other members' signatures. -/
structure AttackerCapabilities where
  ownFalconKey : Bool
  channelPrevPrivateState : Bool
  canMintFreshKeys : Bool
  otherMembersSignatures : Bool
  deriving DecidableEq, Repr

def attacker : AttackerCapabilities :=
  { ownFalconKey := true, channelPrevPrivateState := true,
    canMintFreshKeys := true, otherMembersSignatures := false }

theorem attacker_lacks_other_signatures : attacker.otherMembersSignatures = false := rfl

/-! ## nofn_attack.rs: the five-step §2.1 chain and where it is expected to die -/

/-- The five steps of the design §2.1 chain as the harness walks them. -/
inductive AttackStep where
  /-- Step 1 (lines 286-311): `SpendCircuit` proof of the theft transfer. -/
  | spend
  /-- Step 2 (lines 378-396): `BalanceProcessor::prove_send_tx`. -/
  | sendTx
  /-- Step 3 (lines 450-698): a signing block over `theft_tx_tree_root`. -/
  | signingBlock
  /-- Step 4 (lines 404-424): `SingleWithdawalCircuit` proof. -/
  | singleWithdrawal
  /-- Step 5 (lines 425-448): withdrawal chain + `prove_final`. -/
  | finalWithdrawal
  deriving DecidableEq, Repr

/-- What the harness asserts about each step at HEAD. -/
inductive StepExpectation where
  /-- The step still succeeds; the harness `expect`s a proof. -/
  | stillUnblocked
  /-- The step must fail; the harness asserts refusal. -/
  | refused
  deriving DecidableEq, Repr

def stepExpectation : AttackStep → StepExpectation
  | .spend => .stillUnblocked
  | .sendTx => .stillUnblocked
  | .signingBlock => .refused
  | .singleWithdrawal => .stillUnblocked
  | .finalWithdrawal => .stillUnblocked

/-- The harness's own claim shape (lines 5-8, 700-707): exactly one step is
expected to be refused, and it is the signing block. This is a statement about
the harness's expectations as data, not a proof that the other steps are safe
or that step 3 is unreachable. -/
theorem only_signing_block_is_expected_refused (s : AttackStep) :
    stepExpectation s = .refused ↔ s = .signingBlock := by
  cases s <;> simp [stepExpectation]

/-- The three signing-block shapes available to the attacker (lines 31-35)
plus the two sub-cases of A3 (lines 548-669). -/
inductive SigningShape where
  /-- `signer_count = 1` over the real member set (lines 467-489). -/
  | a1
  /-- `signer_count = 2` over {attacker, freshly minted key} (lines 491-546). -/
  | a2
  /-- `signer_count = 3`, victims' pks under the attacker's own signature (lines 554-583). -/
  | a3a
  /-- a genuine 1-of-N aggregate folded into a list proof (lines 585-669). -/
  | a3b
  deriving DecidableEq, Repr

def shapeSignerCount : SigningShape → Nat
  | .a1 => 1
  | .a2 => 2
  | .a3a => 3
  | .a3b => 1

/-- The production check each shape is attributed to (nofn_attack.rs table at
lines 31-35 and the NAMED CONSTRAINT comments). Line ranges are those of the
current sources. -/
def shapeRefusal : SigningShape → RefusalSite
  | .a1 =>
    { file := updateChannelTreePath, firstLine := 277, lastLine := 282,
      constraint := "2 <= signer_count <= MAX_SIG_CLUSTER (design §5.4 item 2)",
      nativeMessage := "out of range 2..=8" }
  | .a2 =>
    { file := updateChannelTreePath, firstLine := 308, lastLine := 316,
      constraint := "recomputed member_pubkeys_root == channel leaf committed root (design §5.4 item 5)",
      nativeMessage := "does not match the channel leaf's committed root" }
  | .a3a =>
    { file := falconAggPath, firstLine := 0, lastLine := 0,
      constraint := "FalconLeafCircuit unconditional norm bound",
      nativeMessage := "" }
  | .a3b =>
    { file := validityCircuitPath, firstLine := 242, lastLine := 262,
      constraint := "C == final.bp_sig_chain, gated on the computed chain",
      nativeMessage := "" }

/-- The in-circuit counterpart of the two native-mirror rules, which the
harness also exercises via `to_public_inputs_unchecked` (lines 183-189). Not
modeled here; recorded as the boundary it is. -/
def circuitSignerSetSite : RefusalSite :=
  { file := updateChannelTreePath, firstLine := 1049, lastLine := 1260,
    constraint := "in-circuit thermometer, occupancy and member-root connect",
    nativeMessage := "" }

/-- The production entry point the harness also drives (lines 681-698):
`BlockHashChainProcessor::prove_block` must refuse A1 and A2. -/
def proveBlockRefusedShapes : List SigningShape := [.a1, .a2]

theorem no_refusal_is_attributed_to_the_harness (s : SigningShape) :
    (shapeRefusal s).file ≠ nofnAttackPath := by
  cases s <;> decide

theorem a1_and_a2_are_native_mirror_refusals :
    (shapeRefusal .a1).file = updateChannelTreePath ∧
    (shapeRefusal .a2).file = updateChannelTreePath := ⟨rfl, rfl⟩

theorem a3b_is_a_validity_circuit_refusal :
    (shapeRefusal .a3b).file = validityCircuitPath := rfl

/-! ## The signer-set witness shape and the harness's isolation assertions

`UpdateUserTree` carries `signer_count` and all `MAX_SIG_CLUSTER` member
leaves; the channel leaf carries the committed `member_pubkeys_root`. The
harness's isolation predicates (lines 195-201, 458-459, 485-488, 526-541) are
restated executably over this shape. -/

/-- `MemberLeaf { pk_g, pk_b, regev_pk_digest }`; the empty leaf is all-zero
(`MemberLeaf::default()`, key_tree.rs 100-102). Field values are abstract
naturals. -/
structure MemberLeaf where
  pkG : Nat
  pkB : Nat
  regevPkDigest : Nat
  deriving DecidableEq, Repr

def MemberLeaf.empty : MemberLeaf := ⟨0, 0, 0⟩

structure SignerSetWitness where
  signerCount : Nat
  /-- All `maxSigCluster` slots in slot order. -/
  memberLeaves : List MemberLeaf
  /-- `prev_account_leaves[0].member_pubkeys_root`. -/
  committedRoot : Nat
  deriving Repr

/-- Line 530: `(2..=MAX_SIG_CLUSTER).contains(&signer_count)`. -/
def floorSatisfied (w : SignerSetWitness) : Bool :=
  signerCountFloor ≤ w.signerCount && w.signerCount ≤ maxSigCluster

/-- Refusals of the native mirror's signing-slot rules, in check order
(update_channel_tree.rs 277-316). -/
inductive MirrorRefusal where
  | signerCountOutOfRange
  | slotAtOrAboveSignerCountOccupied (slot : Nat)
  | slotBelowSignerCountEmpty (slot : Nat)
  | rootMismatch
  deriving DecidableEq, Repr

/-- Lines 288-300 of update_channel_tree.rs, and the harness's own restatement
at lines 531-541: slot `i < signer_count` must carry a nonzero `pk_g`, slot
`i >= signer_count` must be the empty leaf. First violation in slot order. -/
def paddingViolationFrom (signerCount : Nat) : Nat → List MemberLeaf → Option MirrorRefusal
  | _, [] => none
  | slot, leaf :: rest =>
    if slot < signerCount then
      if leaf.pkG = 0 then some (.slotBelowSignerCountEmpty slot)
      else paddingViolationFrom signerCount (slot + 1) rest
    else
      if leaf = MemberLeaf.empty then paddingViolationFrom signerCount (slot + 1) rest
      else some (.slotAtOrAboveSignerCountOccupied slot)

def paddingViolation (w : SignerSetWitness) : Option MirrorRefusal :=
  paddingViolationFrom w.signerCount 0 w.memberLeaves

def slotsWellPadded (w : SignerSetWitness) : Bool :=
  (paddingViolation w).isNone

/-- The harness helper `member_root_matches` (lines 195-201): recompute the
member tree root over the witnessed leaves and compare with the committed
root. The root function is an opaque parameter (Poseidon MemberTree). -/
def memberRootMatches (root : List MemberLeaf → Nat) (w : SignerSetWitness) : Bool :=
  root w.memberLeaves == w.committedRoot

/-- Handwritten restatement of the three N-of-N rules of
`UpdateUserTree::check_signing_slot` (update_channel_tree.rs 277-316), in
source order: floor, occupancy, root connect. The tx_tree_root != 0 rule
(261-265), the slot-index rules (270-274, 301-305) and the bp Regev binding
(320-324) are not part of the harness's three shapes and are not restated.
This is NOT a model of update_channel_tree.rs; it exists to state, over the
harness's data, which of the three rules each shape trips. -/
def signingSlotMirror (root : List MemberLeaf → Nat) (w : SignerSetWitness) :
    Except MirrorRefusal Unit :=
  if floorSatisfied w then
    match paddingViolation w with
    | some e => .error e
    | none =>
      if root w.memberLeaves = w.committedRoot then .ok () else .error .rootMismatch
  else .error .signerCountOutOfRange

/-! ### The concrete shapes (lines 453-546) -/

/-- Three registered members with distinct nonzero keys; concrete stand-ins
for the fixture's Falcon `pk_g` digests. -/
def memberLeaf0 : MemberLeaf := ⟨0xa0, 0xb0, 0xc0⟩
def memberLeaf1 : MemberLeaf := ⟨0xa1, 0xb1, 0xc1⟩
def memberLeaf2 : MemberLeaf := ⟨0xa2, 0xb2, 0xc2⟩
/-- The key the attacker mints at line 507 (`FalconKeys::from_seed([0x5c; 32])`). -/
def sockPuppetPkG : Nat := 0x5c

def honestLeaves : List MemberLeaf :=
  [memberLeaf0, memberLeaf1, memberLeaf2,
   MemberLeaf.empty, MemberLeaf.empty, MemberLeaf.empty, MemberLeaf.empty, MemberLeaf.empty]

/-- The control: the honest 3-of-3 block (lines 453-465). -/
def honestShape (committed : Nat) : SignerSetWitness :=
  { signerCount := registeredMembers, memberLeaves := honestLeaves, committedRoot := committed }

/-- A1 (lines 483-489): the honest tree with `signer_count = 1`. -/
def a1Shape (committed : Nat) : SignerSetWitness :=
  { honestShape committed with signerCount := 1 }

/-- A2 (lines 516-525): `signer_count = 2`, slot 1's `pk_g` replaced by the
sock puppet (pk_b and regev digest kept), slot 2 blanked. -/
def a2Leaves : List MemberLeaf :=
  [memberLeaf0, { memberLeaf1 with pkG := sockPuppetPkG }, MemberLeaf.empty,
   MemberLeaf.empty, MemberLeaf.empty, MemberLeaf.empty, MemberLeaf.empty, MemberLeaf.empty]

def a2Shape (committed : Nat) : SignerSetWitness :=
  { signerCount := 2, memberLeaves := a2Leaves, committedRoot := committed }

/-- A3 (lines 548-552) reuses the honest tree unchanged: `update_channel_tree`
accepts it and the refusal is one layer up. -/
def a3Shape (committed : Nat) : SignerSetWitness := honestShape committed

theorem honest_leaves_cover_all_slots : honestLeaves.length = maxSigCluster := rfl
theorem a2_leaves_cover_all_slots : a2Leaves.length = maxSigCluster := rfl

theorem shape_signer_counts_pinned (committed : Nat) :
    (honestShape committed).signerCount = 3 ∧ (a1Shape committed).signerCount = 1 ∧
    (a2Shape committed).signerCount = 2 ∧ (a3Shape committed).signerCount = 3 :=
  ⟨rfl, rfl, rfl, rfl⟩

/-- Lines 458-459: the control satisfies the floor and the padding rule. -/
theorem honest_shape_satisfies_floor_and_padding (committed : Nat) :
    floorSatisfied (honestShape committed) = true ∧
    slotsWellPadded (honestShape committed) = true := ⟨rfl, rfl⟩

/-- For any witness that satisfies the floor and the padding rule, the
restated mirror accepts exactly when the recomputed root is the committed
one: the root connect is the last of the three rules. -/
theorem mirror_ok_iff_root_matches (root : List MemberLeaf → Nat) (w : SignerSetWitness)
    (hf : floorSatisfied w = true) (hp : paddingViolation w = none) :
    signingSlotMirror root w = .ok () ↔ root w.memberLeaves = w.committedRoot := by
  unfold signingSlotMirror
  rw [hf, hp]
  by_cases hr : root w.memberLeaves = w.committedRoot
  · simp [hr]
  · simp [hr]

/-- Same premises: a root mismatch yields exactly the root-connect refusal. -/
theorem mirror_root_mismatch_error (root : List MemberLeaf → Nat) (w : SignerSetWitness)
    (hf : floorSatisfied w = true) (hp : paddingViolation w = none)
    (hr : root w.memberLeaves ≠ w.committedRoot) :
    signingSlotMirror root w = .error .rootMismatch := by
  unfold signingSlotMirror
  rw [hf, hp]
  simp [hr]

/-- The control passes the restated mirror exactly when the recomputed root is
the committed one (lines 458, 460-462). -/
theorem honest_shape_passes_mirror_iff_root_matches
    (root : List MemberLeaf → Nat) (committed : Nat) :
    signingSlotMirror root (honestShape committed) = .ok () ↔
      root honestLeaves = committed :=
  mirror_ok_iff_root_matches root (honestShape committed) rfl rfl

/-- A1 (lines 484-488): only `signer_count` changed; the member leaves are the
honest ones, so the root connect is NOT what refuses it. -/
theorem a1_shape_keeps_honest_leaves (committed : Nat) :
    (a1Shape committed).memberLeaves = honestLeaves := rfl

theorem a1_shape_breaks_floor (committed : Nat) :
    floorSatisfied (a1Shape committed) = false := rfl

/-- A1 also violates the padding rule (harness comment at lines 475-479:
slots 1 and 2 hold real members at or above `signer_count = 1`). -/
theorem a1_shape_also_breaks_padding (committed : Nat) :
    paddingViolation (a1Shape committed) = some (.slotAtOrAboveSignerCountOccupied 1) := rfl

/-- The restated mirror refuses A1 by the floor for EVERY root function and
every committed root: the floor is checked first (source order 277 before
288 and 308). This is the attribution the harness asserts at line 489 via the
native message `out of range 2..=8`. -/
theorem a1_shape_refused_by_floor_first (root : List MemberLeaf → Nat) (committed : Nat) :
    signingSlotMirror root (a1Shape committed) = .error .signerCountOutOfRange := rfl

/-- A2 (lines 530-541): the floor is satisfied and slots 0-1 are active while
2..8 are empty, so among the three restated rules only the root connect can
refuse it. -/
theorem a2_shape_satisfies_floor_and_padding (committed : Nat) :
    floorSatisfied (a2Shape committed) = true ∧
    slotsWellPadded (a2Shape committed) = true := ⟨rfl, rfl⟩

theorem a2_shape_differs_from_honest_only_in_slots_1_and_2 :
    a2Leaves[0]? = honestLeaves[0]? ∧
    a2Leaves[1]? ≠ honestLeaves[1]? ∧
    a2Leaves[2]? ≠ honestLeaves[2]? ∧
    a2Leaves.drop 3 = honestLeaves.drop 3 := by
  refine ⟨rfl, ?_, ?_, rfl⟩ <;> decide

/-- Both A2 slots below `signer_count` carry keys the attacker can sign with:
slot 0 is the attacker's own, slot 1 is the minted one (line 507-515). -/
theorem a2_active_slots_are_attacker_controlled :
    (a2Leaves[0]?.map MemberLeaf.pkG) = some memberLeaf0.pkG ∧
    (a2Leaves[1]?.map MemberLeaf.pkG) = some sockPuppetPkG := ⟨rfl, rfl⟩

/-- Under the EXPLICIT premise that the recomputed root over the tampered
leaves differs from the committed root (the harness establishes this at
runtime, lines 526-529, by actually hashing; no hash property is used here),
the restated mirror refuses A2 by the root connect and by nothing earlier.
This matches the message asserted at lines 542-546. -/
theorem a2_shape_refused_by_root_connect_given_mismatch
    (root : List MemberLeaf → Nat) (committed : Nat)
    (hmismatch : root a2Leaves ≠ committed) :
    signingSlotMirror root (a2Shape committed) = .error .rootMismatch :=
  mirror_root_mismatch_error root (a2Shape committed) rfl rfl hmismatch

/-- Isolation, the other direction (harness lines 517-519): if a root function
DID map the tampered leaves to the committed root, the restated mirror would
accept A2 — i.e. the root connect is the only one of the three rules standing
between A2 and acceptance. Whether Poseidon can do so is the collision
boundary, not a claim of this module. -/
theorem a2_shape_accepted_if_root_matched
    (root : List MemberLeaf → Nat) (committed : Nat)
    (hmatch : root a2Leaves = committed) :
    signingSlotMirror root (a2Shape committed) = .ok () :=
  (mirror_ok_iff_root_matches root (a2Shape committed) rfl rfl).2 hmatch

/-- A3 (lines 550-552): the honest tree, which the signing-slot mirror
accepts under the matched root; the refusal the harness attributes lies
outside the three rules restated here. -/
theorem a3_shape_passes_signing_slot_mirror
    (root : List MemberLeaf → Nat) (committed : Nat)
    (hmatch : root honestLeaves = committed) :
    signingSlotMirror root (a3Shape committed) = .ok () :=
  (honest_shape_passes_mirror_iff_root_matches root committed).2 hmatch

/-- The harness's attribution discipline (`assert_refused`, lines 170-190),
as data: a refusal counts only if the strict native mirror rejects naming the
expected reason AND the circuit also rejects when fed the unchecked mirror's
public inputs. -/
structure AttributedRefusal where
  nativeMirrorRejectsNaming : String
  circuitRejectsUncheckedPis : Bool
  deriving DecidableEq, Repr

def attributedRefusal (s : SigningShape) : Option AttributedRefusal :=
  match s with
  | .a1 => some ⟨(shapeRefusal .a1).nativeMessage, true⟩
  | .a2 => some ⟨(shapeRefusal .a2).nativeMessage, true⟩
  | .a3a => none
  | .a3b => none

theorem attributed_refusals_are_exactly_the_mirror_shapes (s : SigningShape) :
    (attributedRefusal s).isSome = true ↔ (s = .a1 ∨ s = .a2) := by
  cases s <;> simp [attributedRefusal]

/-! ## e2e_flow.rs: pinned fixture constants (lines 77-94, 311-354) -/

def inChannelAmount : Nat := 7
def interChannelAmount : Nat := 5
def e2eActive : Nat := 3
def aGenesis : List Nat := [50, 10, 30]
def bGenesis : List Nat := [10, 20, 30]
def channelA : Nat := 5
def channelB : Nat := 7
def aFund : Nat := 100
def bFund : Nat := 200
/-- `constants::MAX_CHANNEL_MEMBERS` (constants.rs line 96). -/
def maxChannelMembers : Nat := 1024
/-- `regev::MAX_HOMO_ADDS_BEFORE_REFRESH` (regev/params.rs line 60). -/
def maxHomoAddsBeforeRefresh : Nat := 64
def happyPathTests : Nat := 2

theorem in_channel_amount_pinned : inChannelAmount = 7 := rfl
theorem inter_channel_amount_pinned : interChannelAmount = 5 := rfl
theorem e2e_active_pinned : e2eActive = 3 := rfl
theorem max_channel_members_pinned : maxChannelMembers = 1024 := rfl
theorem max_homo_adds_pinned : maxHomoAddsBeforeRefresh = 64 := rfl
theorem genesis_arrays_have_active_length :
    aGenesis.length = e2eActive ∧ bGenesis.length = e2eActive := ⟨rfl, rfl⟩

/-- The hidden balances the happy path decrypts (lines 734-742, 762-770,
803-811, 829-833): alice 50-7-5, bob 10+7, dave 10+5. -/
def aliceFinal : Nat := aGenesis.getD 0 0 - inChannelAmount - interChannelAmount
def bobFinal : Nat := aGenesis.getD 1 0 + inChannelAmount
def daveFinal : Nat := bGenesis.getD 0 0 + interChannelAmount

theorem alice_final_pinned : aliceFinal = 38 := rfl
theorem bob_final_pinned : bobFinal = 17 := rfl
theorem dave_final_pinned : daveFinal = 15 := rfl

/-- The public inter-channel amount moves between the two channel funds
(lines 461-466, 559-564): A goes 100 -> 95, B goes 200 -> 205. -/
theorem channel_funds_move_by_inter_channel_amount :
    aFund - interChannelAmount = 95 ∧ bFund + interChannelAmount = 205 := ⟨rfl, rfl⟩

/-- The fixture's fund amounts are NOT the sums of its genesis balances
(90 vs 100, 60 vs 200); nothing in the harness asserts that relation. Recorded
so the fixture is not mistaken for an economically consistent state. -/
theorem fixture_funds_are_not_balance_sums :
    aGenesis.foldl (· + ·) 0 ≠ aFund ∧ bGenesis.foldl (· + ·) 0 ≠ bFund := by
  decide

/-! ## e2e_flow.rs: the structural transport verifier (lines 116-131) -/

inductive FlowErrorKind where
  | proofVerification
  | invalidCiphertextTransition
  | invalidAmountRelation
  | invalidSettledTxChain
  | invalidH2Tag
  | invalidSmallBlock
  | invalidStateVersion
  | invalidPendingAdds
  deriving DecidableEq, Repr

/-- `StructuralTransportVerifier::verify`: accepts exactly an EMPTY proof
envelope and inspects nothing else. Every inter-channel test in the file runs
against this verifier, so no real transport proof is verified anywhere in the
suite. -/
def structuralTransportVerify (proof : List Nat) : Except FlowErrorKind Unit :=
  if proof.isEmpty then .ok () else .error .proofVerification

theorem structural_transport_accepts_only_empty (proof : List Nat) :
    structuralTransportVerify proof = .ok () ↔ proof = [] := by
  unfold structuralTransportVerify
  cases proof with
  | nil => simp
  | cons x xs => simp

/-! ## e2e_flow.rs: the five verifier-checked transitions of the happy path -/

/-- `ChannelTransitionKind` variants the happy path asserts (common/channel.rs). -/
inductive TransitionKind where
  | inChannelTransfer
  | interChannelSend
  | interChannelFundImport
  | receiverBundleApply
  | balanceRefresh
  deriving DecidableEq, Repr

/-- The witness steps of `channel_native_regev_full_flow_e2e` (lines 702-833)
plus the close/claim/cancel/post-close tail (lines 835-955). -/
inductive FlowStep where
  | inChannelTransfer
  | interChannelSend
  | fundImport
  | bundleApply
  | balanceRefresh
  | close
  | withdrawalClaim
  | cancelClose
  | postCloseClaim
  deriving DecidableEq, Repr

/-- What the happy path asserts about one verifier-checked transition. -/
structure TransitionExpectation where
  kind : TransitionKind
  channel : Nat
  prevVersion : Nat
  nextVersion : Nat
  /-- `pis.amount`: zero for hidden in-channel amounts. -/
  publicAmount : Nat
  /-- `pis.h2_tag == tx_tree_root` (true) or `== 0` (false). -/
  h2IsTxTreeRoot : Bool
  /-- `next_settled_tx_chain == push(prev, tx_leaf)` (true) or `== prev` (false). -/
  chainAdvances : Bool
  deriving DecidableEq, Repr

def expectedTransition : FlowStep → Option TransitionExpectation
  | .inChannelTransfer => some
    { kind := .inChannelTransfer, channel := channelA, prevVersion := 0, nextVersion := 1,
      publicAmount := 0, h2IsTxTreeRoot := false, chainAdvances := false }
  | .interChannelSend => some
    { kind := .interChannelSend, channel := channelA, prevVersion := 1, nextVersion := 2,
      publicAmount := interChannelAmount, h2IsTxTreeRoot := true, chainAdvances := true }
  | .fundImport => some
    { kind := .interChannelFundImport, channel := channelB, prevVersion := 0, nextVersion := 1,
      publicAmount := interChannelAmount, h2IsTxTreeRoot := false, chainAdvances := true }
  | .bundleApply => some
    { kind := .receiverBundleApply, channel := channelB, prevVersion := 1, nextVersion := 2,
      publicAmount := interChannelAmount, h2IsTxTreeRoot := false, chainAdvances := false }
  | .balanceRefresh => some
    { kind := .balanceRefresh, channel := channelB, prevVersion := 2, nextVersion := 3,
      publicAmount := 0, h2IsTxTreeRoot := false, chainAdvances := false }
  | .close => none
  | .withdrawalClaim => none
  | .cancelClose => none
  | .postCloseClaim => none

/-- Every asserted transition advances `state_version` by exactly one
(lines 712, 751, 785, 816). Data about the harness's expectations. -/
theorem expected_versions_advance_by_one (s : FlowStep) (e : TransitionExpectation)
    (h : expectedTransition s = some e) : e.nextVersion = e.prevVersion + 1 := by
  cases s <;> simp [expectedTransition] at h <;> subst h <;> rfl

/-- The chain is expected to advance exactly at the two base-settlement steps
(lines 757-761, 776-780) and nowhere else (718-721, 788-791, 817-820). -/
theorem chain_advances_exactly_at_send_and_import (s : FlowStep) (e : TransitionExpectation)
    (h : expectedTransition s = some e) :
    e.chainAdvances = true ↔ (s = .interChannelSend ∨ s = .fundImport) := by
  cases s <;> simp [expectedTransition] at h <;> subst h <;> decide

/-- `H2 = tx_tree_root` is expected only on the inter-channel send (line 753);
every other transition asserts `H2 = 0` (lines 713-717, 786). -/
theorem h2_is_tx_tree_root_only_on_send (s : FlowStep) (e : TransitionExpectation)
    (h : expectedTransition s = some e) :
    e.h2IsTxTreeRoot = true ↔ s = .interChannelSend := by
  cases s <;> simp [expectedTransition] at h <;> subst h <;> decide

/-- The close intent for channel B is expected at `final_state_version = 3`
(line 838), the version the refresh produced. -/
def expectedCloseVersionB : Nat := 3

theorem close_version_is_refresh_next_version :
    (expectedTransition .balanceRefresh).map TransitionExpectation.nextVersion =
      some expectedCloseVersionB := rfl

/-! ## e2e_flow.rs: the negative suite as data (lines 1019-1428) -/

/-- Which witness verifier a negative case drives. -/
inductive Gate where
  | inChannel
  | sourceSend
  | destinationFundImport
  | destinationBundleApply
  deriving DecidableEq, Repr

structure NegativeCase where
  test : String
  firstLine : Nat
  lastLine : Nat
  gates : List Gate
  tamper : String
  /-- Error variants the test's `matches!` accepts. -/
  expected : List FlowErrorKind
  deriving DecidableEq, Repr

def negativeSuite : List NegativeCase :=
  [ { test := "in_channel_tx_without_zkp_is_rejected", firstLine := 1019, lastLine := 1030,
      gates := [.inChannel], tamper := "channel_tx_zkp.proof = []",
      expected := [.proofVerification] },
    { test := "bundle_apply_rejects_tampered_recipient_slot", firstLine := 1032, lastLine := 1049,
      gates := [.destinationBundleApply], tamper := "recipient slot credited twice",
      expected := [.invalidCiphertextTransition] },
    { test := "c2c_rejects_unregistered_token_index_on_both_sides", firstLine := 1051, lastLine := 1080,
      gates := [.sourceSend, .destinationFundImport, .destinationBundleApply],
      tamper := "inter_channel_tx.token_index = 999",
      expected := [.invalidAmountRelation] },
    { test := "bundle_apply_rejects_credit_at_wrong_local_position", firstLine := 1082, lastLine := 1112,
      gates := [.destinationBundleApply], tamper := "credit moved to local position 1",
      expected := [.invalidCiphertextTransition] },
    { test := "receiver_bundle_apply_rejects_second_token_position_credit", firstLine := 1114, lastLine := 1138,
      gates := [.destinationBundleApply], tamper := "position 0 and position 1 both credited",
      expected := [.invalidCiphertextTransition] },
    { test := "c2c_rejects_token_relabeled_descriptor_on_all_gates", firstLine := 1140, lastLine := 1202,
      gates := [.sourceSend, .destinationFundImport, .destinationBundleApply],
      tamper := "token_index relabeled to registered token 55, tx_hash unchanged",
      expected := [.invalidSettledTxChain] },
    { test := "c2c_rejects_synthetic_tx_hash_on_all_gates", firstLine := 1204, lastLine := 1257,
      gates := [.sourceSend, .destinationFundImport, .destinationBundleApply],
      tamper := "tx_hash replaced by a non-recomputed value (message: token-bearing recompute)",
      expected := [.invalidSettledTxChain] },
    { test := "inter_channel_send_rejects_zero_tx_tree_root", firstLine := 1259, lastLine := 1274,
      gates := [.sourceSend], tamper := "signed small block tx_tree_root = 0",
      expected := [.invalidH2Tag] },
    { test := "inter_channel_send_rejects_h2_tag_mismatch", firstLine := 1276, lastLine := 1288,
      gates := [.sourceSend], tamper := "next_state.h2_tag != tx_tree_root",
      expected := [.invalidH2Tag] },
    { test := "inter_channel_send_rejects_state_commitment_root_mismatch", firstLine := 1290, lastLine := 1306,
      gates := [.sourceSend], tamper := "state_commitment_root != next h1",
      expected := [.invalidSmallBlock] },
    { test := "inter_channel_send_rejects_version_skip", firstLine := 1308, lastLine := 1320,
      gates := [.sourceSend], tamper := "next state_version = prev + 2",
      expected := [.invalidStateVersion] },
    { test := "bundle_apply_rejects_pending_adds_over_budget", firstLine := 1322, lastLine := 1340,
      gates := [.destinationBundleApply], tamper := "pending_adds 64 -> 65",
      expected := [.invalidPendingAdds, .invalidCiphertextTransition] },
    { test := "bundle_apply_rejects_accumulator_root_rewrite", firstLine := 1342, lastLine := 1354,
      gates := [.destinationBundleApply], tamper := "settled_tx_accumulator_root rewritten",
      expected := [.invalidSettledTxChain] },
    { test := "inter_channel_send_rejects_wrong_chain_leaf", firstLine := 1356, lastLine := 1378,
      gates := [.sourceSend], tamper := "chain pushed with a foreign leaf",
      expected := [.invalidSettledTxChain] },
    { test := "in_channel_tx_replay_against_other_prev_state_is_rejected", firstLine := 1380, lastLine := 1398,
      gates := [.inChannel], tamper := "prev slot re-encrypted (same balance)",
      expected := [.proofVerification] },
    { test := "inter_channel_send_rejects_e1_proof_in_channel_update_slot", firstLine := 1400, lastLine := 1414,
      gates := [.sourceSend], tamper := "E-1 proof bytes in the E-2 slot",
      expected := [.proofVerification] },
    { test := "bundle_apply_rejects_forged_sender_cts", firstLine := 1416, lastLine := 1428,
      gates := [.destinationBundleApply], tamper := "sender before/after ciphertexts swapped",
      expected := [.proofVerification] } ]

theorem negative_suite_has_seventeen_cases : negativeSuite.length = 17 := rfl

theorem negative_suite_lines_are_ordered :
    ((negativeSuite.map NegativeCase.firstLine).zip (negativeSuite.map NegativeCase.lastLine)).all
      (fun p => decide (p.1 ≤ p.2)) = true := by decide

/-- Every negative case names at least one expected error variant and at
least one gate — no test in the suite accepts "any failure". -/
theorem every_negative_case_names_error_and_gate :
    negativeSuite.all (fun c => !c.expected.isEmpty && !c.gates.isEmpty) = true := by
  decide

/-- Only one negative case accepts two alternative variants (lines 1334-1339,
the budget-vs-validate ambiguity the harness itself documents). -/
theorem only_pending_adds_case_accepts_two_variants :
    (negativeSuite.filter (fun c => c.expected.length ≠ 1)).map NegativeCase.test =
      ["bundle_apply_rejects_pending_adds_over_budget"] := by decide

/-- Total `#[test]` functions in e2e_flow.rs: two happy paths plus the suite. -/
theorem e2e_flow_test_count : happyPathTests + negativeSuite.length = 19 := rfl

end Zkp.Implementation.FlowHarness
