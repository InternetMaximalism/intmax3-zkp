import Std

/-!
# Native prover drivers (processors)

Handwritten source model of the five native prover drivers, read in full:

* `src/circuits/validity/block_hash_chain/block_hash_chain_processor.rs` (477 lines)
* `src/circuits/validity/deposit_hash_chain/deposit_chain_processor.rs` (212 lines)
* `src/circuits/validity/channel_reg_hash_chain/channel_reg_chain_processor.rs` (246 lines)
* `src/circuits/balance/balance_processor.rs` (246 lines)
* `src/circuits/withdraw/withdrawal_processor.rs` (109 lines)

This is NOT a refinement proof of the Rust code, of plonky2, or of any circuit
lowering. Nothing here claims proof soundness, recursion soundness, hash
injectivity, signature validity, or that an accepted proof implies a safe state
transition. What is modeled is exactly what a driver is: an ORDERED CALL PLAN
with error precedence -- which circuit is verified before the next step is
proven, which values are threaded from step to step, which native checks run
before any proving starts, and how `Option` witness fields are resolved to
dummies at the boundary.

Every actual proving and verification call is an opaque callback supplied by an
`Env` record (`proveDepositStep`, `verifyBlockChain`, `parseBlockChainPis`, ...).
Their success or failure is arbitrary input to the model: a theorem saying "the
chain circuit is only called on the step circuit's output" says nothing about
whether either output is sound. The public-input parse of a previous block-chain
proof is likewise an opaque callback; the model does not re-derive the codec.

Deliberate honesty notes:
* Proof objects are `Proof` tokens with a tag and a public-input word list. The
  model never inspects a proof to decide anything, exactly as the drivers do not.
* Digests, Merkle proofs, deposits, records, leaves and tx witnesses are opaque
  `Nat`/record payloads. No tree, hash chain or signature semantics is modeled.
* `BlockHashChainProcessor::new` uses `assert!`, i.e. it panics; that is modeled
  as a distinguished `Construction.panicked`, not as an error value.
* The `#[cfg(test)]` modules of the block, deposit and channel-registration
  processors are NOT modeled and are marked test-only in the line maps.
* `BalanceProcessor::{to_bytes, from_bytes}` are modeled only as an ordered slot
  plan; bincode/serde encoding itself is a dependency boundary.
-/

namespace Zkp.Implementation.Processors

/-! ## Shared vocabulary -/

/-- An opaque 32-byte digest / Poseidon output word. No hash semantics. -/
abbrev Digest := Nat

/-- An opaque plonky2 `VerifierCircuitData` handle. -/
abbrev VerifierData := Nat

/-- An opaque circuit handle. -/
abbrev CircuitId := Nat

/-- An opaque Merkle proof payload. -/
abbrev MerkleProof := Nat

/-- A recursive proof token: the producing circuit's tag plus its public-input
words. The drivers never inspect a proof except through the opaque public-input
parser, and neither does this model. -/
structure Proof where
  tag : String
  pis : List Nat
  deriving DecidableEq, Repr, Inhabited

/-- `is_some as u8`, as the block driver's cardinality check spells it. -/
def flagBit (b : Bool) : Nat := if b then 1 else 0

/-- One node of a constructor's build plan: an artifact and the artifacts that
must already exist when it is produced. -/
structure BuildStep (α : Type) where
  produces : α
  requires : List α
  deriving Repr

/-- A build plan is well ordered when each step's requirements were produced by
an earlier step (or were supplied to the constructor). -/
def buildOrdered [DecidableEq α] : List (BuildStep α) → List α → Bool
  | [], _ => true
  | s :: rest, avail => s.requires.all (fun a => avail.contains a) && buildOrdered rest (s.produces :: avail)

/-- Pinned from `src/constants.rs:135`. -/
def maxSigCluster : Nat := 8

/-- Pinned from `src/constants.rs:282` (`TX_TREE_HEIGHT = CHANNEL_ID_BITS = 32`). -/
def txTreeHeight : Nat := 32

/-- Pinned from `src/regev/params.rs:29`. -/
def regevN : Nat := 2048

/-- `U63::new` rejects values above `2^63 - 1`, so `BlockNumber::add(1)` fails
exactly at this value. -/
def u63Max : Nat := 9223372036854775807

theorem max_sig_cluster_pinned : maxSigCluster = 8 := rfl

theorem tx_tree_height_pinned : txTreeHeight = 32 := rfl

theorem regev_n_pinned : regevN = 2048 := rfl

theorem u63_max_pinned : u63Max = 2 ^ 63 - 1 := by decide

/-! ## `deposit_chain_processor.rs`

`DepositChainProcessor` is a two-circuit driver: the step circuit proves one
deposit against the cyclic chain verifier data, and the hash-chain wrapper
circuit wraps that step proof. `prove_step` is the only proving entry point and
it makes exactly those two calls, in that order. -/

namespace DepositChain

/-- Opaque deposit record; only the fields the driver threads are named. -/
structure Deposit where
  depositIndex : Nat
  blockNumber : Nat
  payload : Nat
  deriving DecidableEq, Repr, Inhabited

/-- `DepositStepWitness`. `initialValue` is the
`(deposit_hash_chain, deposit_tree_root, deposit_count)` seed used only by the
first step of a chain; every later step carries `prevChainProof` instead. -/
structure StepWitness where
  initialValue : Option (Digest × Digest × Nat)
  prevChainProof : Option Proof
  deposit : Deposit
  merkleProof : MerkleProof
  deriving DecidableEq, Repr

/-- `DepositChainProcessorError`. -/
inductive Error where
  | depositStepCircuit (message : String)
  | depositHashChainCircuit (message : String)
  deriving DecidableEq, Repr

/-- The native calls `prove_step` makes, in order. -/
inductive Call where
  | proveDepositStep (chainVd : VerifierData) (witness : StepWitness)
  | proveDepositHashChain (stepProof : Proof)
  deriving DecidableEq, Repr

/-- Artifacts `DepositChainProcessor::new` builds. -/
inductive Artifact where
  | chainCd | stepCircuit | stepVd | chainCircuit | chainVd
  deriving DecidableEq, Repr

/-- `new`: `generate_cd` first, then the step circuit over that common data,
then the chain circuit over that common data AND the step circuit's verifier
data. `deposit_chain_vd()` reads the chain circuit's verifier data. -/
def buildPlan : List (BuildStep Artifact) :=
  [ ⟨.chainCd, []⟩,
    ⟨.stepCircuit, [.chainCd]⟩,
    ⟨.stepVd, [.stepCircuit]⟩,
    ⟨.chainCircuit, [.chainCd, .stepVd]⟩,
    ⟨.chainVd, [.chainCircuit]⟩ ]

/-- The three circuit handles a constructed processor holds. -/
structure Circuit where
  chainCd : Nat
  stepCircuit : CircuitId
  chainCircuit : CircuitId
  deriving DecidableEq, Repr

/-- Every proving and verification call is a dependency boundary. -/
structure Env where
  circuit : Circuit
  vdOf : CircuitId → VerifierData
  proveStepCircuit : VerifierData → StepWitness → Except String Proof
  proveChainCircuit : Proof → Except String Proof
  verifyChainCircuit : Proof → Except String Unit

/-- `deposit_chain_vd()`: the chain circuit's own verifier data, which is also
the cyclic key handed back into the step circuit at prove time. -/
def Env.chainVd (e : Env) : VerifierData := e.vdOf e.circuit.chainCircuit

/-- `prove_step`, as calls made and result returned. -/
def proveStepRun (e : Env) (w : StepWitness) : List Call × Except Error Proof :=
  match e.proveStepCircuit e.chainVd w with
  | .error m => ([.proveDepositStep e.chainVd w], .error (.depositStepCircuit m))
  | .ok sp =>
      match e.proveChainCircuit sp with
      | .error m =>
          ([.proveDepositStep e.chainVd w, .proveDepositHashChain sp],
           .error (.depositHashChainCircuit m))
      | .ok cp =>
          ([.proveDepositStep e.chainVd w, .proveDepositHashChain sp], .ok cp)

def proveStepCalls (e : Env) (w : StepWitness) : List Call := (proveStepRun e w).1

def proveStep (e : Env) (w : StepWitness) : Except Error Proof := (proveStepRun e w).2

/-- `verify` delegates to the hash-chain circuit only. -/
def verify (e : Env) (p : Proof) : Except String Unit := e.verifyChainCircuit p

end DepositChain

theorem deposit_build_plan_is_ordered :
    buildOrdered DepositChain.buildPlan [] = true := by decide

theorem deposit_chain_circuit_binds_step_verifier_data :
    DepositChain.buildPlan[3]?.map BuildStep.requires
      = some [DepositChain.Artifact.chainCd, DepositChain.Artifact.stepVd] := by decide

theorem deposit_prove_step_calls_step_circuit_first (e : DepositChain.Env)
    (w : DepositChain.StepWitness) :
    (DepositChain.proveStepCalls e w).head? = some (.proveDepositStep e.chainVd w) := by
  simp only [DepositChain.proveStepCalls, DepositChain.proveStepRun]
  split
  · rfl
  · split <;> rfl

theorem deposit_prove_step_uses_own_chain_verifier_data (e : DepositChain.Env)
    (w : DepositChain.StepWitness) :
    (DepositChain.proveStepCalls e w).head?
      = some (.proveDepositStep (e.vdOf e.circuit.chainCircuit) w) :=
  deposit_prove_step_calls_step_circuit_first e w

theorem deposit_step_failure_skips_chain_circuit (e : DepositChain.Env)
    (w : DepositChain.StepWitness) (m : String)
    (h : e.proveStepCircuit e.chainVd w = .error m) :
    DepositChain.proveStepCalls e w = [.proveDepositStep e.chainVd w]
      ∧ DepositChain.proveStep e w = .error (.depositStepCircuit m) := by
  constructor
  · simp only [DepositChain.proveStepCalls, DepositChain.proveStepRun, h]
  · simp only [DepositChain.proveStep, DepositChain.proveStepRun, h]

theorem deposit_prove_step_wraps_step_proof (e : DepositChain.Env)
    (w : DepositChain.StepWitness) (p : Proof) (h : DepositChain.proveStep e w = .ok p) :
    ∃ sp, e.proveStepCircuit e.chainVd w = .ok sp
      ∧ e.proveChainCircuit sp = .ok p
      ∧ DepositChain.proveStepCalls e w
          = [.proveDepositStep e.chainVd w, .proveDepositHashChain sp] := by
  simp only [DepositChain.proveStep, DepositChain.proveStepRun] at h
  split at h
  · exact absurd h (by simp)
  · next sp hs =>
    split at h
    · exact absurd h (by simp)
    · next cp hc =>
      have hcp : cp = p := by simpa using h
      subst hcp
      exact ⟨sp, hs, hc, by simp only [DepositChain.proveStepCalls, DepositChain.proveStepRun, hs, hc]⟩

theorem deposit_step_calls_begin_with_the_step_circuit (e : DepositChain.Env)
    (w : DepositChain.StepWitness) :
    ∃ tl, DepositChain.proveStepCalls e w = .proveDepositStep e.chainVd w :: tl := by
  simp only [DepositChain.proveStepCalls, DepositChain.proveStepRun]
  split
  · exact ⟨[], rfl⟩
  · next sp _ => split <;> exact ⟨[.proveDepositHashChain sp], rfl⟩

theorem deposit_verify_uses_chain_circuit_only (e : DepositChain.Env) (p : Proof) :
    DepositChain.verify e p = e.verifyChainCircuit p := rfl

/-! ### A concrete successful deposit step -/

namespace DepositChain

def exampleCircuit : Circuit := ⟨0, 1, 2⟩

def exampleEnv : Env where
  circuit := exampleCircuit
  vdOf := fun c => c + 100
  proveStepCircuit := fun vd w => .ok ⟨"deposit_step", [vd, w.deposit.depositIndex]⟩
  proveChainCircuit := fun p => .ok ⟨"deposit_chain", p.pis⟩
  verifyChainCircuit := fun _ => .ok ()

def exampleWitness : StepWitness where
  initialValue := some (0, 0, 0)
  prevChainProof := none
  deposit := ⟨7, 0, 0⟩
  merkleProof := 0

end DepositChain

theorem deposit_example_step_succeeds :
    DepositChain.proveStep DepositChain.exampleEnv DepositChain.exampleWitness
      = .ok ⟨"deposit_chain", [102, 7]⟩ := rfl

theorem deposit_example_step_makes_two_calls :
    (DepositChain.proveStepCalls DepositChain.exampleEnv DepositChain.exampleWitness).length
      = 2 := rfl

/-! ## `channel_reg_chain_processor.rs`

An explicit mirror of the deposit chain driver, with one extra threaded value:
the block number of the registration block, which the driver's caller supplies
per step. -/

namespace ChannelRegChain

/-- Opaque `ChannelRegRecord`; only the identity the driver threads is named. -/
structure Record where
  channelId : Nat
  memberCount : Nat
  payload : Nat
  deriving DecidableEq, Repr, Inhabited

/-- `ChannelRegStepWitness`. `initialValue` is
`(channel_reg_hash_chain, channel_tree_root, channel_reg_count)`. -/
structure StepWitness where
  initialValue : Option (Digest × Digest × Nat)
  prevChainProof : Option Proof
  record : Record
  channelMerkleProof : MerkleProof
  blockNumber : Nat
  deriving DecidableEq, Repr

/-- `ChannelRegChainProcessorError`. -/
inductive Error where
  | channelRegStepCircuit (message : String)
  | channelRegHashChainCircuit (message : String)
  deriving DecidableEq, Repr

inductive Call where
  | proveChannelRegStep (chainVd : VerifierData) (witness : StepWitness)
  | proveChannelRegHashChain (stepProof : Proof)
  deriving DecidableEq, Repr

inductive Artifact where
  | chainCd | stepCircuit | stepVd | chainCircuit | chainVd
  deriving DecidableEq, Repr

def buildPlan : List (BuildStep Artifact) :=
  [ ⟨.chainCd, []⟩,
    ⟨.stepCircuit, [.chainCd]⟩,
    ⟨.stepVd, [.stepCircuit]⟩,
    ⟨.chainCircuit, [.chainCd, .stepVd]⟩,
    ⟨.chainVd, [.chainCircuit]⟩ ]

structure Circuit where
  chainCd : Nat
  stepCircuit : CircuitId
  chainCircuit : CircuitId
  deriving DecidableEq, Repr

structure Env where
  circuit : Circuit
  vdOf : CircuitId → VerifierData
  proveStepCircuit : VerifierData → StepWitness → Except String Proof
  proveChainCircuit : Proof → Except String Proof
  verifyChainCircuit : Proof → Except String Unit

def Env.chainVd (e : Env) : VerifierData := e.vdOf e.circuit.chainCircuit

def proveStepRun (e : Env) (w : StepWitness) : List Call × Except Error Proof :=
  match e.proveStepCircuit e.chainVd w with
  | .error m => ([.proveChannelRegStep e.chainVd w], .error (.channelRegStepCircuit m))
  | .ok sp =>
      match e.proveChainCircuit sp with
      | .error m =>
          ([.proveChannelRegStep e.chainVd w, .proveChannelRegHashChain sp],
           .error (.channelRegHashChainCircuit m))
      | .ok cp =>
          ([.proveChannelRegStep e.chainVd w, .proveChannelRegHashChain sp], .ok cp)

def proveStepCalls (e : Env) (w : StepWitness) : List Call := (proveStepRun e w).1

def proveStep (e : Env) (w : StepWitness) : Except Error Proof := (proveStepRun e w).2

def verify (e : Env) (p : Proof) : Except String Unit := e.verifyChainCircuit p

/-- `impl Default for ChannelRegChainProcessor` forwards to `new`, so a default
processor runs exactly the same build plan. -/
def defaultBuildPlan : List (BuildStep Artifact) := buildPlan

end ChannelRegChain

theorem channel_reg_build_plan_is_ordered :
    buildOrdered ChannelRegChain.buildPlan [] = true := by decide

theorem channel_reg_default_equals_new_build_plan :
    ChannelRegChain.defaultBuildPlan = ChannelRegChain.buildPlan := rfl

theorem channel_reg_build_plan_mirrors_deposit_build_plan :
    ChannelRegChain.buildPlan.map (fun s => s.requires.length)
      = DepositChain.buildPlan.map (fun s => s.requires.length) := by decide

theorem channel_reg_prove_step_calls_step_circuit_first (e : ChannelRegChain.Env)
    (w : ChannelRegChain.StepWitness) :
    (ChannelRegChain.proveStepCalls e w).head?
      = some (.proveChannelRegStep e.chainVd w) := by
  simp only [ChannelRegChain.proveStepCalls, ChannelRegChain.proveStepRun]
  split
  · rfl
  · split <;> rfl

theorem channel_reg_step_failure_skips_chain_circuit (e : ChannelRegChain.Env)
    (w : ChannelRegChain.StepWitness) (m : String)
    (h : e.proveStepCircuit e.chainVd w = .error m) :
    ChannelRegChain.proveStepCalls e w = [.proveChannelRegStep e.chainVd w]
      ∧ ChannelRegChain.proveStep e w = .error (.channelRegStepCircuit m) := by
  constructor
  · simp only [ChannelRegChain.proveStepCalls, ChannelRegChain.proveStepRun, h]
  · simp only [ChannelRegChain.proveStep, ChannelRegChain.proveStepRun, h]

theorem channel_reg_prove_step_wraps_step_proof (e : ChannelRegChain.Env)
    (w : ChannelRegChain.StepWitness) (p : Proof)
    (h : ChannelRegChain.proveStep e w = .ok p) :
    ∃ sp, e.proveStepCircuit e.chainVd w = .ok sp
      ∧ e.proveChainCircuit sp = .ok p
      ∧ ChannelRegChain.proveStepCalls e w
          = [.proveChannelRegStep e.chainVd w, .proveChannelRegHashChain sp] := by
  simp only [ChannelRegChain.proveStep, ChannelRegChain.proveStepRun] at h
  split at h
  · exact absurd h (by simp)
  · next sp hs =>
    split at h
    · exact absurd h (by simp)
    · next cp hc =>
      have hcp : cp = p := by simpa using h
      subst hcp
      exact ⟨sp, hs, hc,
        by simp only [ChannelRegChain.proveStepCalls, ChannelRegChain.proveStepRun, hs, hc]⟩

theorem channel_reg_step_calls_begin_with_the_step_circuit (e : ChannelRegChain.Env)
    (w : ChannelRegChain.StepWitness) :
    ∃ tl, ChannelRegChain.proveStepCalls e w = .proveChannelRegStep e.chainVd w :: tl := by
  simp only [ChannelRegChain.proveStepCalls, ChannelRegChain.proveStepRun]
  split
  · exact ⟨[], rfl⟩
  · next sp _ => split <;> exact ⟨[.proveChannelRegHashChain sp], rfl⟩

/-! ## `block_hash_chain_processor.rs`

The top validity driver. It owns the deposit and channel-registration
processors, one `UpdateUserCircuit` per supported user count, the block step
circuit and the block hash chain circuit. -/

namespace BlockChain

/-- `Block`, reduced to the field the driver reads plus an opaque remainder. -/
structure Block where
  numUsers : Nat
  payload : Nat
  deriving DecidableEq, Repr, Inhabited

/-- `PublicState`. -/
structure PublicState where
  blockNumber : Nat
  timestamp : Nat
  accountTreeRoot : Digest
  depositTreeRoot : Digest
  prevPublicStateRoot : Digest
  deriving DecidableEq, Repr, Inhabited

/-- `ExtendedPublicState`. -/
structure ExtPublicState where
  inner : PublicState
  blockHashChain : Digest
  depositHashChain : Digest
  depositCount : Nat
  channelRegHashChain : Digest
  bpSigChain : Digest
  deriving DecidableEq, Repr, Inhabited

/-- `MemberLeaf`, opaque. -/
structure MemberLeaf where
  word : Nat
  deriving DecidableEq, Repr, Inhabited

def MemberLeaf.dflt : MemberLeaf := ⟨0⟩

/-- `RegevPk` as a pair of coefficient vectors. -/
structure RegevPk where
  a : List Nat
  b : List Nat
  deriving DecidableEq, Repr, Inhabited

/-- `dummy_regev_pk()`: all-zero coefficients of the correct length. -/
def dummyRegevPk : RegevPk := ⟨List.replicate regevN 0, List.replicate regevN 0⟩

/-- `ChannelStateMessageFields`, opaque. -/
structure ChannelStateFields where
  word : Nat
  deriving DecidableEq, Repr, Inhabited

def ChannelStateFields.dflt : ChannelStateFields := ⟨0⟩

/-- `TxV2`, opaque. -/
structure TxV2 where
  word : Nat
  deriving DecidableEq, Repr, Inhabited

def TxV2.dflt : TxV2 := ⟨0⟩

/-- `ChannelActionKind`. -/
inductive ActionKind where
  | interChannelSend | channelClose | memberSetUpdate
  deriving DecidableEq, Repr, Inhabited

/-- `ChannelAction`, reduced to the kind (which decides `is_member_update`) plus
an opaque payload. -/
structure ChannelAction where
  kind : ActionKind
  payload : Nat
  deriving DecidableEq, Repr, Inhabited

/-- `ChannelAction::default()` has kind `InterChannelSend` (src/common/tx.rs:307). -/
def ChannelAction.dflt : ChannelAction := ⟨.interChannelSend, 0⟩

/-- The predicate the SECURITY (M-2) note is about. -/
def ChannelAction.isMemberUpdate (a : ChannelAction) : Bool :=
  match a.kind with
  | .memberSetUpdate => true
  | _ => false

/-- `TxV2MerkleProof::dummy(h)` / `ChannelActionMerkleProof::dummy(h)`; the
height is the only thing the driver chooses. -/
def dummyMerkleProof (height : Nat) : MerkleProof := height

/-- `BlockHashChainProcessorWitness`. -/
structure Witness where
  depositStepWitness : List (DepositChain.Deposit × MerkleProof)
  channelRegStepWitness : List (ChannelRegChain.Record × MerkleProof)
  block : Block
  prevAccountLeaves : List Nat
  userMerkleProofs : List MerkleProof
  sendMerkleProofs : List MerkleProof
  publicStateMerkleProof : MerkleProof
  memberLeaves : Option (List MemberLeaf)
  newMemberLeaves : Option (List MemberLeaf)
  signerCount : Option Nat
  memberRegevPks : Option (List RegevPk)
  channelStateFields : Option ChannelStateFields
  txV2Indices : Option (List Nat)
  txV2s : Option (List TxV2)
  txV2MerkleProofs : Option (List MerkleProof)
  channelActionIndices : Option (List Nat)
  channelActions : Option (List ChannelAction)
  channelActionMerkleProofs : Option (List MerkleProof)
  deriving DecidableEq, Repr

/-- `UpdateUserTree`, the value fed to the per-user-count circuit. -/
structure UpdateUserTree where
  prevBlockHashChain : Digest
  prevAccountTreeRoot : Digest
  blockNumber : Nat
  block : Block
  prevAccountLeaves : List Nat
  userMerkleProofs : List MerkleProof
  sendMerkleProofs : List MerkleProof
  prevBpSigChain : Digest
  memberLeaves : List MemberLeaf
  newMemberLeaves : List MemberLeaf
  signerCount : Nat
  memberRegevPks : List RegevPk
  channelStateFields : ChannelStateFields
  txV2Indices : List Nat
  txV2s : List TxV2
  txV2MerkleProofs : List MerkleProof
  channelActionIndices : List Nat
  channelActions : List ChannelAction
  channelActionMerkleProofs : List MerkleProof
  deriving DecidableEq, Repr

/-- `BlockHashChainProcessorWitness::to_update_channel_tree` -- the single place
where every `Option` is resolved to its dummy. -/
def Witness.toUpdateChannelTree (w : Witness) (prev : ExtPublicState)
    (blockNumber : Nat) : UpdateUserTree :=
  let numUsers := w.block.numUsers
  { prevBlockHashChain := prev.blockHashChain
    prevAccountTreeRoot := prev.inner.accountTreeRoot
    blockNumber := blockNumber
    block := w.block
    prevAccountLeaves := w.prevAccountLeaves
    userMerkleProofs := w.userMerkleProofs
    sendMerkleProofs := w.sendMerkleProofs
    prevBpSigChain := prev.bpSigChain
    memberLeaves := w.memberLeaves.getD (List.replicate maxSigCluster MemberLeaf.dflt)
    newMemberLeaves := w.newMemberLeaves.getD []
    signerCount := w.signerCount.getD 0
    memberRegevPks := w.memberRegevPks.getD (List.replicate numUsers dummyRegevPk)
    channelStateFields := w.channelStateFields.getD ChannelStateFields.dflt
    txV2Indices := w.txV2Indices.getD (List.replicate numUsers 0)
    txV2s := w.txV2s.getD (List.replicate numUsers TxV2.dflt)
    txV2MerkleProofs := w.txV2MerkleProofs.getD
      (List.replicate numUsers (dummyMerkleProof txTreeHeight))
    channelActionIndices := w.channelActionIndices.getD (List.replicate numUsers 0)
    channelActions := w.channelActions.getD (List.replicate numUsers ChannelAction.dflt)
    channelActionMerkleProofs := w.channelActionMerkleProofs.getD
      (List.replicate numUsers (dummyMerkleProof txTreeHeight)) }

/-- `BlockStepWitness`, as the driver assembles it. -/
structure BlockStepWitness where
  numUsers : Nat
  initialPublicState : Option ExtPublicState
  prevBlockChainProof : Option Proof
  depositHashChainProof : Option Proof
  channelRegHashChainProof : Option Proof
  updateUserProof : Proof
  publicStateMerkleProof : MerkleProof
  deriving DecidableEq, Repr

/-- `BlockHashChainProcessorError`. -/
inductive Error where
  | unsupportedUserCount (numUsers : Nat)
  | invalidInput (message : String)
  | depositChainProcessor (inner : DepositChain.Error)
  | channelRegChainProcessor (inner : ChannelRegChain.Error)
  | updateUserCircuit (message : String)
  | blockStep (message : String)
  | blockHashChain (message : String)
  deriving DecidableEq, Repr

/-- Calls made after the previous-proof admission checks. This type has NO
verification constructor: the driver verifies nothing else natively. -/
inductive TailCall where
  | depositStep (inner : DepositChain.Call)
  | channelRegStep (inner : ChannelRegChain.Call)
  | proveUpdateUser (numUsers : Nat) (tree : UpdateUserTree)
  | proveBlockStep (witness : BlockStepWitness)
  | proveBlockHashChain (stepProof : Proof)
  deriving DecidableEq, Repr

/-- Every native call `prove_block` makes, in order. -/
inductive Call where
  | verifyPrevBlockChainProof (proof : Proof)
  | parsePrevBlockChainPis (proof : Proof)
  | tail (inner : TailCall)
  deriving DecidableEq, Repr

/-- The only native proof verification the driver performs. -/
def Call.isNativeVerify : Call → Bool
  | .verifyPrevBlockChainProof _ => true
  | _ => false

/-- Artifacts `BlockHashChainProcessor::new` builds, in dependency order. -/
inductive Artifact where
  | blockChainCd
  | depositProcessor | depositChainVd
  | channelRegProcessor | channelRegChainVd
  | updateUserCircuits | updateUserVds
  | blockStepCircuit | blockStepVd
  | blockHashChainCircuit
  deriving DecidableEq, Repr

def buildPlan : List (BuildStep Artifact) :=
  [ ⟨.blockChainCd, []⟩,
    ⟨.depositProcessor, []⟩,
    ⟨.depositChainVd, [.depositProcessor]⟩,
    ⟨.channelRegProcessor, []⟩,
    ⟨.channelRegChainVd, [.channelRegProcessor]⟩,
    ⟨.updateUserCircuits, []⟩,
    ⟨.updateUserVds, [.updateUserCircuits]⟩,
    ⟨.blockStepCircuit, [.blockChainCd, .updateUserVds, .depositChainVd, .channelRegChainVd]⟩,
    ⟨.blockStepVd, [.blockStepCircuit]⟩,
    ⟨.blockHashChainCircuit, [.blockChainCd, .blockStepVd]⟩ ]

/-- `new` panics (`assert!`) on an empty supported-user-count list; it is not an
error value. -/
inductive Construction where
  | panicked (message : String)
  | built (registeredUserCounts : List Nat)
  deriving DecidableEq, Repr

def newProcessor (supportedUserCounts : List Nat) : Construction :=
  if supportedUserCounts.isEmpty then
    .panicked "at least one supported user count is required"
  else
    .built supportedUserCounts

/-- Dependency boundary for every proving, verification and codec call. -/
structure Env where
  registeredUserCounts : List Nat
  depositEnv : DepositChain.Env
  channelRegEnv : ChannelRegChain.Env
  verifyBlockChain : Proof → Except String Unit
  parseBlockChainPis : Proof → Except String ExtPublicState
  proveUpdateUser : Nat → UpdateUserTree → Except String Proof
  proveBlockStep : BlockStepWitness → Except String Proof
  proveBlockHashChain : Proof → Except String Proof

/-- The `HashMap` lookup `update_user_circuits.get(&num_users)`. -/
def Env.updateUserCircuit (e : Env) (numUsers : Nat) : Option Nat :=
  if e.registeredUserCounts.contains numUsers then some numUsers else none

/-- The witness the deposit fold builds for one step: `initial_value` is
supplied only while no chain proof exists yet, otherwise the previous chain
proof is threaded instead. -/
def depositStepWitnessFor (seed : Digest × Digest × Nat) (acc : Option Proof)
    (d : DepositChain.Deposit) (mp : MerkleProof) : DepositChain.StepWitness :=
  { initialValue := if acc.isNone then some seed else none
    prevChainProof := acc
    deposit := d
    merkleProof := mp }

/-- The deposit chain fold. -/
def runDepositChain (de : DepositChain.Env) (seed : Digest × Digest × Nat) :
    List (DepositChain.Deposit × MerkleProof) → Option Proof →
    List DepositChain.Call × Except DepositChain.Error (Option Proof)
  | [], acc => ([], .ok acc)
  | (d, mp) :: rest, acc =>
      let step := DepositChain.proveStepRun de (depositStepWitnessFor seed acc d mp)
      match step.2 with
      | .error err => (step.1, .error err)
      | .ok p =>
          let rec' := runDepositChain de seed rest (some p)
          (step.1 ++ rec'.1, rec'.2)

/-- The channel-registration chain fold: the same shape, plus the block number
threaded into every step witness. -/
def channelRegStepWitnessFor (seed : Digest × Digest × Nat) (blockNumber : Nat)
    (acc : Option Proof) (r : ChannelRegChain.Record) (mp : MerkleProof) :
    ChannelRegChain.StepWitness :=
  { initialValue := if acc.isNone then some seed else none
    prevChainProof := acc
    record := r
    channelMerkleProof := mp
    blockNumber := blockNumber }

def runChannelRegChain (ce : ChannelRegChain.Env) (seed : Digest × Digest × Nat)
    (blockNumber : Nat) :
    List (ChannelRegChain.Record × MerkleProof) → Option Proof →
    List ChannelRegChain.Call × Except ChannelRegChain.Error (Option Proof)
  | [], acc => ([], .ok acc)
  | (r, mp) :: rest, acc =>
      let step := ChannelRegChain.proveStepRun ce (channelRegStepWitnessFor seed blockNumber acc r mp)
      match step.2 with
      | .error err => (step.1, .error err)
      | .ok p =>
          let rec' := runChannelRegChain ce seed blockNumber rest (some p)
          (step.1 ++ rec'.1, rec'.2)

/-- The deposit chain seed read out of the previous extended public state. -/
def depositSeed (prev : ExtPublicState) : Digest × Digest × Nat :=
  (prev.depositHashChain, prev.inner.depositTreeRoot, prev.depositCount)

/-- The channel-registration chain seed. NOTE: the third component is
`U63::default()`, i.e. the registration count restarts at zero for every block;
the previous state carries no registration count to thread. The root component
is the ACCOUNT tree root, not the deposit tree root. -/
def channelRegSeed (prev : ExtPublicState) : Digest × Digest × Nat :=
  (prev.channelRegHashChain, prev.inner.accountTreeRoot, 0)

def originMessage : String :=
  "either initial public state or previous block chain proof must be provided"

def blockNumberOverflowMessage : String := "previous block number is at max value"

def missingInitialStateMessage : String := "initial public state must be provided"

def parseFailureMessage (m : String) : String :=
  "failed to parse previous block chain proof public inputs: " ++ m

/-- Everything after the previous-state resolution: deposit chain, block number,
channel-registration chain, update-user proof, block step, block hash chain. -/
def proveBlockTail (e : Env) (initialPublicState : Option ExtPublicState)
    (prevBlockChainProof : Option Proof) (w : Witness) (prev : ExtPublicState) :
    List TailCall × Except Error Proof :=
  let dep := runDepositChain e.depositEnv (depositSeed prev) w.depositStepWitness none
  let depCalls := dep.1.map TailCall.depositStep
  match dep.2 with
  | .error err => (depCalls, .error (.depositChainProcessor err))
  | .ok depositProof =>
      if prev.inner.blockNumber + 1 > u63Max then
        (depCalls, .error (.invalidInput blockNumberOverflowMessage))
      else
        let blockNumber := prev.inner.blockNumber + 1
        let reg := runChannelRegChain e.channelRegEnv (channelRegSeed prev) blockNumber
          w.channelRegStepWitness none
        let regCalls := reg.1.map TailCall.channelRegStep
        match reg.2 with
        | .error err => (depCalls ++ regCalls, .error (.channelRegChainProcessor err))
        | .ok regProof =>
            let tree := w.toUpdateChannelTree prev blockNumber
            let userCall := TailCall.proveUpdateUser w.block.numUsers tree
            match e.proveUpdateUser w.block.numUsers tree with
            | .error m => (depCalls ++ regCalls ++ [userCall], .error (.updateUserCircuit m))
            | .ok userProof =>
                let bsw : BlockStepWitness :=
                  { numUsers := w.block.numUsers
                    initialPublicState := initialPublicState
                    prevBlockChainProof := prevBlockChainProof
                    depositHashChainProof := depositProof
                    channelRegHashChainProof := regProof
                    updateUserProof := userProof
                    publicStateMerkleProof := w.publicStateMerkleProof }
                let pre := depCalls ++ regCalls ++ [userCall, TailCall.proveBlockStep bsw]
                match e.proveBlockStep bsw with
                | .error m => (pre, .error (.blockStep m))
                | .ok stepProof =>
                    match e.proveBlockHashChain stepProof with
                    | .error m =>
                        (pre ++ [TailCall.proveBlockHashChain stepProof],
                         .error (.blockHashChain m))
                    | .ok p => (pre ++ [TailCall.proveBlockHashChain stepProof], .ok p)

/-- `prove_block`. -/
def proveBlockRun (e : Env) (initialPublicState : Option ExtPublicState)
    (prevBlockChainProof : Option Proof) (w : Witness) :
    List Call × Except Error Proof :=
  match e.updateUserCircuit w.block.numUsers with
  | none => ([], .error (.unsupportedUserCount w.block.numUsers))
  | some _ =>
      if flagBit initialPublicState.isSome + flagBit prevBlockChainProof.isSome ≠ 1 then
        ([], .error (.invalidInput originMessage))
      else
        match prevBlockChainProof with
        | some proof =>
            match e.verifyBlockChain proof with
            | .error m => ([.verifyPrevBlockChainProof proof], .error (.blockHashChain m))
            | .ok () =>
                match e.parseBlockChainPis proof with
                | .error m =>
                    ([.verifyPrevBlockChainProof proof, .parsePrevBlockChainPis proof],
                     .error (.invalidInput (parseFailureMessage m)))
                | .ok prev =>
                    let t := proveBlockTail e initialPublicState prevBlockChainProof w prev
                    ([.verifyPrevBlockChainProof proof, .parsePrevBlockChainPis proof]
                       ++ t.1.map Call.tail, t.2)
        | none =>
            match initialPublicState with
            | some prev =>
                let t := proveBlockTail e initialPublicState prevBlockChainProof w prev
                (t.1.map Call.tail, t.2)
            | none => ([], .error (.invalidInput missingInitialStateMessage))

def proveBlockCalls (e : Env) (i : Option ExtPublicState) (p : Option Proof) (w : Witness) :
    List Call := (proveBlockRun e i p w).1

def proveBlock (e : Env) (i : Option ExtPublicState) (p : Option Proof) (w : Witness) :
    Except Error Proof := (proveBlockRun e i p w).2

def verify (e : Env) (p : Proof) : Except String Unit := e.verifyBlockChain p

end BlockChain

/-! ### Constructor -/

theorem block_build_plan_is_ordered :
    buildOrdered BlockChain.buildPlan [] = true := by decide

theorem block_step_circuit_binds_all_four_verifier_keys :
    BlockChain.buildPlan[7]?.map BuildStep.requires
      = some [BlockChain.Artifact.blockChainCd, BlockChain.Artifact.updateUserVds,
              BlockChain.Artifact.depositChainVd, BlockChain.Artifact.channelRegChainVd] := by
  decide

theorem block_hash_chain_circuit_binds_block_step_verifier_data :
    BlockChain.buildPlan[9]?.map BuildStep.requires
      = some [BlockChain.Artifact.blockChainCd, BlockChain.Artifact.blockStepVd] := by decide

theorem block_new_panics_on_empty_supported_counts :
    BlockChain.newProcessor []
      = .panicked "at least one supported user count is required" := rfl

theorem block_new_registers_every_supported_count (counts : List Nat) (h : counts ≠ []) :
    BlockChain.newProcessor counts = .built counts := by
  cases counts with
  | nil => exact absurd rfl h
  | cons a as => rfl

/-! ### Dummy resolution in `to_update_channel_tree` -/

theorem block_tree_threads_previous_extended_state (w : BlockChain.Witness)
    (prev : BlockChain.ExtPublicState) (bn : Nat) :
    (w.toUpdateChannelTree prev bn).prevBlockHashChain = prev.blockHashChain
      ∧ (w.toUpdateChannelTree prev bn).prevAccountTreeRoot = prev.inner.accountTreeRoot
      ∧ (w.toUpdateChannelTree prev bn).prevBpSigChain = prev.bpSigChain
      ∧ (w.toUpdateChannelTree prev bn).blockNumber = bn
      ∧ (w.toUpdateChannelTree prev bn).block = w.block :=
  ⟨rfl, rfl, rfl, rfl, rfl⟩

theorem block_tree_defaults_member_set_to_full_cluster (w : BlockChain.Witness)
    (prev : BlockChain.ExtPublicState) (bn : Nat) (h : w.memberLeaves = none) :
    (w.toUpdateChannelTree prev bn).memberLeaves.length = maxSigCluster
      ∧ (w.toUpdateChannelTree prev bn).signerCount = w.signerCount.getD 0 := by
  simp [BlockChain.Witness.toUpdateChannelTree, h]

theorem block_tree_defaults_signer_count_to_zero (w : BlockChain.Witness)
    (prev : BlockChain.ExtPublicState) (bn : Nat) (h : w.signerCount = none) :
    (w.toUpdateChannelTree prev bn).signerCount = 0 := by
  simp [BlockChain.Witness.toUpdateChannelTree, h]

theorem block_tree_defaults_new_member_leaves_to_empty (w : BlockChain.Witness)
    (prev : BlockChain.ExtPublicState) (bn : Nat) (h : w.newMemberLeaves = none) :
    (w.toUpdateChannelTree prev bn).newMemberLeaves = [] := by
  simp [BlockChain.Witness.toUpdateChannelTree, h]

theorem block_tree_dummy_regev_keys_have_pinned_length (w : BlockChain.Witness)
    (prev : BlockChain.ExtPublicState) (bn : Nat) (h : w.memberRegevPks = none) :
    (w.toUpdateChannelTree prev bn).memberRegevPks.length = w.block.numUsers
      ∧ ∀ k ∈ (w.toUpdateChannelTree prev bn).memberRegevPks,
          k.a.length = regevN ∧ k.b.length = regevN := by
  constructor
  · simp [BlockChain.Witness.toUpdateChannelTree, h]
  · intro k hk
    simp only [BlockChain.Witness.toUpdateChannelTree, h, Option.getD] at hk
    rw [List.eq_of_mem_replicate hk]
    simp [BlockChain.dummyRegevPk]

theorem block_tree_dummy_slot_vectors_match_user_count (w : BlockChain.Witness)
    (prev : BlockChain.ExtPublicState) (bn : Nat)
    (h1 : w.txV2Indices = none) (h2 : w.txV2s = none) (h3 : w.txV2MerkleProofs = none)
    (h4 : w.channelActionIndices = none) (h5 : w.channelActionMerkleProofs = none) :
    (w.toUpdateChannelTree prev bn).txV2Indices.length = w.block.numUsers
      ∧ (w.toUpdateChannelTree prev bn).txV2s.length = w.block.numUsers
      ∧ (w.toUpdateChannelTree prev bn).txV2MerkleProofs.length = w.block.numUsers
      ∧ (w.toUpdateChannelTree prev bn).channelActionIndices.length = w.block.numUsers
      ∧ (w.toUpdateChannelTree prev bn).channelActionMerkleProofs.length = w.block.numUsers := by
  simp [BlockChain.Witness.toUpdateChannelTree, h1, h2, h3, h4, h5]

/-- SECURITY (M-2), restated as a fact about the substitution: a `None`
`channel_actions` does not merely omit an unused witness, it fills every slot
with an action whose kind makes `is_member_update` FALSE. -/
theorem block_default_channel_actions_are_never_member_updates (w : BlockChain.Witness)
    (prev : BlockChain.ExtPublicState) (bn : Nat) (h : w.channelActions = none) :
    ∀ a ∈ (w.toUpdateChannelTree prev bn).channelActions, a.isMemberUpdate = false := by
  intro a ha
  simp only [BlockChain.Witness.toUpdateChannelTree, h, Option.getD] at ha
  rw [List.eq_of_mem_replicate ha]
  rfl

theorem block_tree_uses_supplied_options_verbatim (w : BlockChain.Witness)
    (prev : BlockChain.ExtPublicState) (bn : Nat) (ml : List BlockChain.MemberLeaf)
    (ca : List BlockChain.ChannelAction) (sc : Nat)
    (h1 : w.memberLeaves = some ml) (h2 : w.channelActions = some ca)
    (h3 : w.signerCount = some sc) :
    (w.toUpdateChannelTree prev bn).memberLeaves = ml
      ∧ (w.toUpdateChannelTree prev bn).channelActions = ca
      ∧ (w.toUpdateChannelTree prev bn).signerCount = sc := by
  simp [BlockChain.Witness.toUpdateChannelTree, h1, h2, h3]

theorem block_dummy_tx_merkle_proofs_use_pinned_height (w : BlockChain.Witness)
    (prev : BlockChain.ExtPublicState) (bn : Nat) (h : w.txV2MerkleProofs = none) :
    ∀ p ∈ (w.toUpdateChannelTree prev bn).txV2MerkleProofs, p = txTreeHeight := by
  intro p hp
  simp only [BlockChain.Witness.toUpdateChannelTree, h, Option.getD] at hp
  rw [List.eq_of_mem_replicate hp]
  rfl

/-! ### Admission checks that run before any proving -/

theorem block_unsupported_user_count_stops_before_any_call (e : BlockChain.Env)
    (i : Option BlockChain.ExtPublicState) (p : Option Proof) (w : BlockChain.Witness)
    (h : e.updateUserCircuit w.block.numUsers = none) :
    BlockChain.proveBlockCalls e i p w = []
      ∧ BlockChain.proveBlock e i p w = .error (.unsupportedUserCount w.block.numUsers) := by
  constructor
  · simp only [BlockChain.proveBlockCalls, BlockChain.proveBlockRun, h]
  · simp only [BlockChain.proveBlock, BlockChain.proveBlockRun, h]

theorem block_requires_exactly_one_origin (e : BlockChain.Env)
    (i : Option BlockChain.ExtPublicState) (p : Option Proof) (w : BlockChain.Witness)
    (h : flagBit i.isSome + flagBit p.isSome ≠ 1) :
    BlockChain.proveBlockCalls e i p w = []
      ∧ (BlockChain.proveBlock e i p w = .error (.unsupportedUserCount w.block.numUsers)
         ∨ BlockChain.proveBlock e i p w = .error (.invalidInput BlockChain.originMessage)) := by
  simp only [BlockChain.proveBlockCalls, BlockChain.proveBlock, BlockChain.proveBlockRun]
  split
  · exact ⟨rfl, Or.inl rfl⟩
  · rw [if_pos h]
    exact ⟨rfl, Or.inr rfl⟩

/-- The `initial public state must be provided` arm of the source is dead code:
the cardinality check above already guarantees an initial state whenever the
previous proof is absent. -/
theorem block_missing_initial_state_arm_is_unreachable (i : Option BlockChain.ExtPublicState)
    (h : flagBit i.isSome + flagBit (none : Option Proof).isSome = 1) :
    i.isSome = true := by
  simp only [Option.isSome_none, flagBit] at h
  cases hi : i.isSome with
  | true => rfl
  | false => rw [hi] at h; simp [flagBit] at h

/-- The cardinality check passes for the chained origin (no initial state, a
previous proof). -/
theorem block_chained_origin_is_admitted (proof : Proof) :
    ¬ (flagBit (none : Option BlockChain.ExtPublicState).isSome + flagBit (some proof).isSome ≠ 1) := by
  simp [flagBit]

/-- The cardinality check passes for the genesis origin. -/
theorem block_genesis_origin_is_admitted (prev : BlockChain.ExtPublicState) :
    ¬ (flagBit (some prev).isSome + flagBit (none : Option Proof).isSome ≠ 1) := by
  simp [flagBit]

/-! ### Verification of the previous proof precedes all proving -/

theorem block_verifies_previous_proof_first (e : BlockChain.Env)
    (i : Option BlockChain.ExtPublicState) (proof : Proof) (w : BlockChain.Witness) :
    (BlockChain.proveBlockCalls e i (some proof) w).head? = some (.verifyPrevBlockChainProof proof)
      ∨ BlockChain.proveBlockCalls e i (some proof) w = [] := by
  simp only [BlockChain.proveBlockCalls, BlockChain.proveBlockRun]
  split
  · exact Or.inr rfl
  · split
    · exact Or.inr rfl
    · split
      · exact Or.inl rfl
      · split
        · exact Or.inl rfl
        · exact Or.inl rfl

theorem block_previous_proof_verification_failure_stops_all_proving (e : BlockChain.Env)
    (proof : Proof) (w : BlockChain.Witness)
    (hc : e.updateUserCircuit w.block.numUsers = some w.block.numUsers)
    (m : String) (h : e.verifyBlockChain proof = .error m) :
    BlockChain.proveBlockCalls e none (some proof) w = [.verifyPrevBlockChainProof proof]
      ∧ BlockChain.proveBlock e none (some proof) w = .error (.blockHashChain m) := by
  constructor
  · simp only [BlockChain.proveBlockCalls, BlockChain.proveBlockRun, hc,
      if_neg (block_chained_origin_is_admitted proof), h]
  · simp only [BlockChain.proveBlock, BlockChain.proveBlockRun, hc,
      if_neg (block_chained_origin_is_admitted proof), h]

theorem block_public_input_parse_failure_stops_all_proving (e : BlockChain.Env)
    (proof : Proof) (w : BlockChain.Witness)
    (hc : e.updateUserCircuit w.block.numUsers = some w.block.numUsers)
    (hv : e.verifyBlockChain proof = .ok ())
    (m : String) (h : e.parseBlockChainPis proof = .error m) :
    BlockChain.proveBlockCalls e none (some proof) w
        = [.verifyPrevBlockChainProof proof, .parsePrevBlockChainPis proof]
      ∧ BlockChain.proveBlock e none (some proof) w
        = .error (.invalidInput (BlockChain.parseFailureMessage m)) := by
  constructor
  · simp only [BlockChain.proveBlockCalls, BlockChain.proveBlockRun, hc,
      if_neg (block_chained_origin_is_admitted proof), hv, h]
  · simp only [BlockChain.proveBlock, BlockChain.proveBlockRun, hc,
      if_neg (block_chained_origin_is_admitted proof), hv, h]

/-- Genesis: with an initial extended public state and no previous proof, no
verification and no public-input parse happen at all. -/
theorem block_genesis_run_skips_verification_and_parse (e : BlockChain.Env)
    (prev : BlockChain.ExtPublicState) (w : BlockChain.Witness)
    (hc : e.updateUserCircuit w.block.numUsers = some w.block.numUsers) :
    BlockChain.proveBlockCalls e (some prev) none w
      = (BlockChain.proveBlockTail e (some prev) none w prev).1.map BlockChain.Call.tail
    ∧ BlockChain.proveBlock e (some prev) none w
      = (BlockChain.proveBlockTail e (some prev) none w prev).2 := by
  constructor
  · simp only [BlockChain.proveBlockCalls, BlockChain.proveBlockRun, hc, if_neg (block_genesis_origin_is_admitted prev)]
  · simp only [BlockChain.proveBlock, BlockChain.proveBlockRun, hc, if_neg (block_genesis_origin_is_admitted prev)]

/-- Calls made after the previous-proof admission checks can never be a native
verification: `TailCall` has no verification constructor, which is the model's
way of recording that the driver hands the deposit chain, channel-registration
chain and update-user proofs to the block step circuit unverified natively. -/
theorem block_tail_calls_are_never_native_verifies (t : List BlockChain.TailCall) :
    ∀ c ∈ t.map BlockChain.Call.tail, c.isNativeVerify = false := by
  intro c hc
  simp only [List.mem_map] at hc
  obtain ⟨x, _, hx⟩ := hc
  rw [← hx]
  rfl

/-- A genesis run performs no native proof verification at all. -/
theorem block_genesis_run_makes_no_native_verify_call (e : BlockChain.Env)
    (i : Option BlockChain.ExtPublicState) (w : BlockChain.Witness) :
    ∀ c ∈ BlockChain.proveBlockCalls e i none w, c.isNativeVerify = false := by
  intro c hc
  simp only [BlockChain.proveBlockCalls, BlockChain.proveBlockRun] at hc
  split at hc
  · simp at hc
  · split at hc
    · simp at hc
    · split at hc
      · exact block_tail_calls_are_never_native_verifies _ c hc
      · simp at hc

/-! ### Step ordering and value threading inside the tail -/

theorem block_empty_deposit_chain_makes_no_call (de : DepositChain.Env)
    (seed : Digest × Digest × Nat) (acc : Option Proof) :
    BlockChain.runDepositChain de seed [] acc = ([], .ok acc) := rfl

theorem block_empty_channel_reg_chain_makes_no_call (ce : ChannelRegChain.Env)
    (seed : Digest × Digest × Nat) (bn : Nat) (acc : Option Proof) :
    BlockChain.runChannelRegChain ce seed bn [] acc = ([], .ok acc) := rfl

theorem block_deposit_loop_calls_the_step_driver_first (de : DepositChain.Env)
    (seed : Digest × Digest × Nat) (d : DepositChain.Deposit) (mp : MerkleProof)
    (rest : List (DepositChain.Deposit × MerkleProof)) (acc : Option Proof) :
    (BlockChain.runDepositChain de seed ((d, mp) :: rest) acc).1.head?
      = some (.proveDepositStep de.chainVd (BlockChain.depositStepWitnessFor seed acc d mp)) := by
  obtain ⟨tl, htl⟩ :=
    deposit_step_calls_begin_with_the_step_circuit de (BlockChain.depositStepWitnessFor seed acc d mp)
  simp only [DepositChain.proveStepCalls] at htl
  simp only [BlockChain.runDepositChain]
  split <;> rw [htl] <;> rfl

/-- Only the first step of a block's deposit chain carries the seed read out of
the previous extended public state. -/
theorem block_deposit_chain_seeds_only_the_first_step (seed : Digest × Digest × Nat)
    (d : DepositChain.Deposit) (mp : MerkleProof) (prevProof : Proof) :
    BlockChain.depositStepWitnessFor seed none d mp
        = { initialValue := some seed, prevChainProof := none, deposit := d, merkleProof := mp }
      ∧ BlockChain.depositStepWitnessFor seed (some prevProof) d mp
        = { initialValue := none, prevChainProof := some prevProof, deposit := d,
            merkleProof := mp } := ⟨rfl, rfl⟩

theorem block_channel_reg_loop_calls_the_step_driver_first (ce : ChannelRegChain.Env)
    (seed : Digest × Digest × Nat) (bn : Nat) (r : ChannelRegChain.Record) (mp : MerkleProof)
    (rest : List (ChannelRegChain.Record × MerkleProof)) (acc : Option Proof) :
    (BlockChain.runChannelRegChain ce seed bn ((r, mp) :: rest) acc).1.head?
      = some (.proveChannelRegStep ce.chainVd
          (BlockChain.channelRegStepWitnessFor seed bn acc r mp)) := by
  obtain ⟨tl, htl⟩ := channel_reg_step_calls_begin_with_the_step_circuit ce
    (BlockChain.channelRegStepWitnessFor seed bn acc r mp)
  simp only [ChannelRegChain.proveStepCalls] at htl
  simp only [BlockChain.runChannelRegChain]
  split <;> rw [htl] <;> rfl

/-- Every registration step of one block is proven at the SAME block number, and
only the first carries the seed. -/
theorem block_channel_reg_chain_threads_block_number (seed : Digest × Digest × Nat) (bn : Nat)
    (r : ChannelRegChain.Record) (mp : MerkleProof) (acc : Option Proof) (prevProof : Proof) :
    (BlockChain.channelRegStepWitnessFor seed bn acc r mp).blockNumber = bn
      ∧ (BlockChain.channelRegStepWitnessFor seed bn none r mp).initialValue = some seed
      ∧ (BlockChain.channelRegStepWitnessFor seed bn (some prevProof) r mp).initialValue
          = none := ⟨rfl, rfl, rfl⟩

theorem block_channel_reg_chain_seeds_count_zero (prev : BlockChain.ExtPublicState) :
    (BlockChain.channelRegSeed prev).2.2 = 0 := rfl

theorem block_channel_reg_chain_seeds_account_tree_root (prev : BlockChain.ExtPublicState) :
    (BlockChain.channelRegSeed prev).1 = prev.channelRegHashChain
      ∧ (BlockChain.channelRegSeed prev).2.1 = prev.inner.accountTreeRoot := ⟨rfl, rfl⟩

theorem block_deposit_chain_seeds_deposit_tree_root (prev : BlockChain.ExtPublicState) :
    BlockChain.depositSeed prev
      = (prev.depositHashChain, prev.inner.depositTreeRoot, prev.depositCount) := rfl

/-- The block number increment happens AFTER the whole deposit chain has been
proven, so an at-max previous block number is reported only once every deposit
step proof has already been produced. -/
theorem block_number_overflow_is_reported_after_deposit_steps (e : BlockChain.Env)
    (i : Option BlockChain.ExtPublicState) (p : Option Proof) (w : BlockChain.Witness)
    (prev : BlockChain.ExtPublicState) (dp : Option Proof)
    (hd : (BlockChain.runDepositChain e.depositEnv (BlockChain.depositSeed prev)
            w.depositStepWitness none).2 = .ok dp)
    (ho : prev.inner.blockNumber + 1 > u63Max) :
    BlockChain.proveBlockTail e i p w prev
      = ((BlockChain.runDepositChain e.depositEnv (BlockChain.depositSeed prev)
            w.depositStepWitness none).1.map BlockChain.TailCall.depositStep,
         .error (.invalidInput BlockChain.blockNumberOverflowMessage)) := by
  simp only [BlockChain.proveBlockTail, hd, if_pos ho]

theorem block_number_is_previous_plus_one (e : BlockChain.Env)
    (i : Option BlockChain.ExtPublicState) (p : Option Proof) (w : BlockChain.Witness)
    (prev : BlockChain.ExtPublicState) (dp : Option Proof)
    (hd : (BlockChain.runDepositChain e.depositEnv (BlockChain.depositSeed prev)
            w.depositStepWitness none).2 = .ok dp)
    (ho : ¬ prev.inner.blockNumber + 1 > u63Max) :
    BlockChain.proveBlockTail e i p w prev
      = (let bn := prev.inner.blockNumber + 1
         let reg := BlockChain.runChannelRegChain e.channelRegEnv
           (BlockChain.channelRegSeed prev) bn w.channelRegStepWitness none
         let depCalls := (BlockChain.runDepositChain e.depositEnv (BlockChain.depositSeed prev)
           w.depositStepWitness none).1.map BlockChain.TailCall.depositStep
         let regCalls := reg.1.map BlockChain.TailCall.channelRegStep
         match reg.2 with
         | .error err => (depCalls ++ regCalls, .error (.channelRegChainProcessor err))
         | .ok regProof =>
             let tree := w.toUpdateChannelTree prev bn
             let userCall := BlockChain.TailCall.proveUpdateUser w.block.numUsers tree
             match e.proveUpdateUser w.block.numUsers tree with
             | .error m => (depCalls ++ regCalls ++ [userCall], .error (.updateUserCircuit m))
             | .ok userProof =>
                 let bsw : BlockChain.BlockStepWitness :=
                   { numUsers := w.block.numUsers, initialPublicState := i,
                     prevBlockChainProof := p, depositHashChainProof := dp,
                     channelRegHashChainProof := regProof, updateUserProof := userProof,
                     publicStateMerkleProof := w.publicStateMerkleProof }
                 let pre := depCalls ++ regCalls ++ [userCall, BlockChain.TailCall.proveBlockStep bsw]
                 match e.proveBlockStep bsw with
                 | .error m => (pre, .error (.blockStep m))
                 | .ok stepProof =>
                     match e.proveBlockHashChain stepProof with
                     | .error m =>
                         (pre ++ [BlockChain.TailCall.proveBlockHashChain stepProof],
                          .error (.blockHashChain m))
                     | .ok q => (pre ++ [BlockChain.TailCall.proveBlockHashChain stepProof], .ok q)) := by
  simp only [BlockChain.proveBlockTail, hd, if_neg ho]

/-- Success threads every intermediate proof into the block step witness, and
the driver's own output is exactly the block-hash-chain circuit's output. -/
theorem block_success_threads_every_intermediate_proof (e : BlockChain.Env)
    (i : Option BlockChain.ExtPublicState) (p : Option Proof) (w : BlockChain.Witness)
    (prev : BlockChain.ExtPublicState) (out : Proof)
    (h : (BlockChain.proveBlockTail e i p w prev).2 = .ok out) :
    ∃ dp rp up sp,
      (BlockChain.runDepositChain e.depositEnv (BlockChain.depositSeed prev)
          w.depositStepWitness none).2 = .ok dp
      ∧ e.proveUpdateUser w.block.numUsers
          (w.toUpdateChannelTree prev (prev.inner.blockNumber + 1)) = .ok up
      ∧ e.proveBlockStep
          { numUsers := w.block.numUsers, initialPublicState := i, prevBlockChainProof := p,
            depositHashChainProof := dp, channelRegHashChainProof := rp,
            updateUserProof := up, publicStateMerkleProof := w.publicStateMerkleProof }
          = .ok sp
      ∧ e.proveBlockHashChain sp = .ok out := by
  simp only [BlockChain.proveBlockTail] at h
  split at h
  · exact absurd h (by simp)
  · next dp hdp =>
    split at h
    · exact absurd h (by simp)
    · split at h
      · exact absurd h (by simp)
      · next rp _ =>
        split at h
        · exact absurd h (by simp)
        · next up hup =>
          split at h
          · exact absurd h (by simp)
          · next sp hsp =>
            split at h
            · exact absurd h (by simp)
            · next q hq =>
              refine ⟨dp, rp, up, sp, hdp, hup, hsp, ?_⟩
              have : q = out := by simpa using h
              rw [hq, this]

theorem block_verify_uses_hash_chain_circuit_only (e : BlockChain.Env) (p : Proof) :
    BlockChain.verify e p = e.verifyBlockChain p := rfl

/-! ### A concrete successful genesis block -/

namespace BlockChain

def exampleState : ExtPublicState where
  inner := ⟨0, 0, 11, 12, 13⟩
  blockHashChain := 20
  depositHashChain := 21
  depositCount := 0
  channelRegHashChain := 22
  bpSigChain := 23

def exampleWitness : Witness where
  depositStepWitness := []
  channelRegStepWitness := []
  block := ⟨2, 0⟩
  prevAccountLeaves := []
  userMerkleProofs := []
  sendMerkleProofs := []
  publicStateMerkleProof := 0
  memberLeaves := none
  newMemberLeaves := none
  signerCount := none
  memberRegevPks := none
  channelStateFields := none
  txV2Indices := none
  txV2s := none
  txV2MerkleProofs := none
  channelActionIndices := none
  channelActions := none
  channelActionMerkleProofs := none

def exampleEnv : Env where
  registeredUserCounts := [2]
  depositEnv := DepositChain.exampleEnv
  channelRegEnv :=
    { circuit := ⟨0, 1, 2⟩
      vdOf := fun c => c + 200
      proveStepCircuit := fun vd _ => .ok ⟨"channel_reg_step", [vd]⟩
      proveChainCircuit := fun p => .ok ⟨"channel_reg_chain", p.pis⟩
      verifyChainCircuit := fun _ => .ok () }
  verifyBlockChain := fun _ => .ok ()
  parseBlockChainPis := fun _ => .ok exampleState
  proveUpdateUser := fun n _ => .ok ⟨"update_user", [n]⟩
  proveBlockStep := fun bsw => .ok ⟨"block_step", [bsw.numUsers]⟩
  proveBlockHashChain := fun p => .ok ⟨"block_hash_chain", p.pis⟩

end BlockChain

theorem block_example_genesis_succeeds :
    BlockChain.proveBlock BlockChain.exampleEnv (some BlockChain.exampleState) none
        BlockChain.exampleWitness = .ok ⟨"block_hash_chain", [2]⟩ := rfl

theorem block_example_genesis_makes_three_calls :
    (BlockChain.proveBlockCalls BlockChain.exampleEnv (some BlockChain.exampleState) none
      BlockChain.exampleWitness).length = 3 := rfl

theorem block_example_both_origins_is_rejected :
    BlockChain.proveBlock BlockChain.exampleEnv (some BlockChain.exampleState)
        (some ⟨"block_hash_chain", []⟩) BlockChain.exampleWitness
      = .error (.invalidInput BlockChain.originMessage) := rfl

theorem block_example_unsupported_user_count_is_rejected :
    BlockChain.proveBlock BlockChain.exampleEnv (some BlockChain.exampleState) none
        { BlockChain.exampleWitness with block := ⟨3, 0⟩ }
      = .error (.unsupportedUserCount 3) := rfl

/-! ## `balance_processor.rs`

Four entry points that all end in the same two calls: the switch board circuit
(against the balance circuit's own verifier data) and the balance circuit. The
genesis entry point `prove_initial` proves no leaf circuit at all. -/

namespace Balance

inductive Mode where
  | initial | receiveTransfer | receiveDeposit | sendTx
  deriving DecidableEq, Repr

/-- Opaque leaf witness (`ReceiveTransferWitness` / `ReceiveDepositWitness` /
`SendTxWitness`). -/
structure LeafWitness where
  word : Nat
  deriving DecidableEq, Repr, Inhabited

/-- `BalanceSwichBoard`. -/
structure SwitchBoardWitness where
  initialValue : Option (Nat × Nat)
  receiveTransferProof : Option Proof
  receiveDepositProof : Option Proof
  sendTxProof : Option Proof
  deriving DecidableEq, Repr

/-- How many of the four switch-board slots are populated. -/
def SwitchBoardWitness.filled (w : SwitchBoardWitness) : Nat :=
  flagBit w.initialValue.isSome + flagBit w.receiveTransferProof.isSome
    + flagBit w.receiveDepositProof.isSome + flagBit w.sendTxProof.isSome

/-- `BalanceProcessorError`. -/
inductive Error where
  | receiveTransferCircuit (message : String)
  | receiveDepositCircuit (message : String)
  | sendTxCircuit (message : String)
  | switchBoardCircuit (message : String)
  | balanceCircuit (message : String)
  deriving DecidableEq, Repr

inductive Call where
  | proveLeaf (mode : Mode) (witness : LeafWitness)
  | proveSwitchBoard (balanceVd : VerifierData) (witness : SwitchBoardWitness)
  | proveBalance (switchBoardProof : Proof)
  deriving DecidableEq, Repr

/-- Whether a call proves one of the three leaf (branch) circuits. -/
def Call.isLeafProof : Call → Bool
  | .proveLeaf _ _ => true
  | _ => false

inductive Artifact where
  | balanceCd
  | receiveTransferCircuit | receiveTransferVd
  | receiveDepositCircuit | receiveDepositVd
  | sendTxCircuit | sendTxVd
  | switchBoardCircuit | switchBoardVd
  | balanceCircuit | balanceVd
  deriving DecidableEq, Repr

/-- `new` also consumes an externally supplied `spend_vd`, which is a parameter,
not a produced artifact; it is available from the start. -/
def buildPlan : List (BuildStep Artifact) :=
  [ ⟨.balanceCd, []⟩,
    ⟨.receiveTransferCircuit, [.balanceCd]⟩,
    ⟨.receiveTransferVd, [.receiveTransferCircuit]⟩,
    ⟨.receiveDepositCircuit, [.balanceCd]⟩,
    ⟨.receiveDepositVd, [.receiveDepositCircuit]⟩,
    ⟨.sendTxCircuit, [.balanceCd]⟩,
    ⟨.sendTxVd, [.sendTxCircuit]⟩,
    ⟨.switchBoardCircuit, [.balanceCd, .receiveTransferVd, .receiveDepositVd, .sendTxVd]⟩,
    ⟨.switchBoardVd, [.switchBoardCircuit]⟩,
    ⟨.balanceCircuit, [.balanceCd, .switchBoardVd]⟩,
    ⟨.balanceVd, [.balanceCircuit]⟩ ]

structure Env where
  balanceVd : VerifierData
  proveLeaf : Mode → LeafWitness → Except String Proof
  proveSwitchBoard : VerifierData → SwitchBoardWitness → Except String Proof
  proveBalance : Proof → Except String Proof

/-- The error constructor each leaf circuit's failure is mapped to. -/
def leafError : Mode → String → Error
  | .initial, m => .switchBoardCircuit m
  | .receiveTransfer, m => .receiveTransferCircuit m
  | .receiveDeposit, m => .receiveDepositCircuit m
  | .sendTx, m => .sendTxCircuit m

/-- The switch-board witness each entry point assembles. -/
def switchBoardWitness : Mode → Proof → SwitchBoardWitness
  | .initial, _ => ⟨none, none, none, none⟩
  | .receiveTransfer, p => ⟨none, some p, none, none⟩
  | .receiveDeposit, p => ⟨none, none, some p, none⟩
  | .sendTx, p => ⟨none, none, none, some p⟩

/-- The tail every entry point shares: switch board, then balance circuit. -/
def finish (e : Env) (w : SwitchBoardWitness) : List Call × Except Error Proof :=
  match e.proveSwitchBoard e.balanceVd w with
  | .error m => ([.proveSwitchBoard e.balanceVd w], .error (.switchBoardCircuit m))
  | .ok sp =>
      match e.proveBalance sp with
      | .error m =>
          ([.proveSwitchBoard e.balanceVd w, .proveBalance sp], .error (.balanceCircuit m))
      | .ok p => ([.proveSwitchBoard e.balanceVd w, .proveBalance sp], .ok p)

/-- `prove_initial`: genesis. No leaf circuit is proven. -/
def proveInitialRun (e : Env) (channelId salt : Nat) : List Call × Except Error Proof :=
  finish e ⟨some (channelId, salt), none, none, none⟩

/-- The shape of the three non-genesis entry points. -/
def proveLeafRun (e : Env) (m : Mode) (lw : LeafWitness) : List Call × Except Error Proof :=
  match e.proveLeaf m lw with
  | .error msg => ([.proveLeaf m lw], .error (leafError m msg))
  | .ok p =>
      let t := finish e (switchBoardWitness m p)
      (.proveLeaf m lw :: t.1, t.2)

def proveReceiveTransferRun (e : Env) (lw : LeafWitness) : List Call × Except Error Proof :=
  proveLeafRun e .receiveTransfer lw

def proveReceiveDepositRun (e : Env) (lw : LeafWitness) : List Call × Except Error Proof :=
  proveLeafRun e .receiveDeposit lw

def proveSendTxRun (e : Env) (lw : LeafWitness) : List Call × Except Error Proof :=
  proveLeafRun e .sendTx lw

/-- `to_bytes` / `from_bytes` slot order (`BalanceProcessorBytes`). Bincode
itself is a dependency boundary. -/
inductive Slot where
  | receiveTransfer | receiveDeposit | sendTx | switchBoard | balance
  deriving DecidableEq, Repr

def serializeOrder : List Slot := [.receiveTransfer, .receiveDeposit, .sendTx, .switchBoard, .balance]

def deserializeOrder : List Slot := [.receiveTransfer, .receiveDeposit, .sendTx, .switchBoard, .balance]

end Balance

theorem balance_build_plan_is_ordered :
    buildOrdered Balance.buildPlan [] = true := by decide

theorem balance_switch_board_binds_all_three_branch_keys :
    Balance.buildPlan[7]?.map BuildStep.requires
      = some [Balance.Artifact.balanceCd, Balance.Artifact.receiveTransferVd,
              Balance.Artifact.receiveDepositVd, Balance.Artifact.sendTxVd] := by decide

theorem balance_circuit_binds_switch_board_verifier_data :
    Balance.buildPlan[9]?.map BuildStep.requires
      = some [Balance.Artifact.balanceCd, Balance.Artifact.switchBoardVd] := by decide

theorem balance_finish_calls_shape (e : Balance.Env) (w : Balance.SwitchBoardWitness) :
    (Balance.finish e w).1 = [.proveSwitchBoard e.balanceVd w]
      ∨ ∃ sp, (Balance.finish e w).1
          = [.proveSwitchBoard e.balanceVd w, .proveBalance sp] := by
  simp only [Balance.finish]
  split
  · exact Or.inl rfl
  · next sp _ => split <;> exact Or.inr ⟨sp, rfl⟩

/-- `prove_initial` is the genesis entry point: it proves NO leaf circuit, only
the switch board and the balance circuit. -/
theorem balance_genesis_proves_no_leaf_circuit (e : Balance.Env) (channelId salt : Nat) :
    ∀ c ∈ (Balance.proveInitialRun e channelId salt).1, c.isLeafProof = false := by
  intro c hc
  simp only [Balance.proveInitialRun] at hc
  rcases balance_finish_calls_shape e ⟨some (channelId, salt), none, none, none⟩ with h | ⟨sp, h⟩
  · rw [h] at hc
    simp only [List.mem_singleton] at hc
    subst hc
    rfl
  · rw [h] at hc
    simp only [List.mem_cons, List.mem_singleton, List.not_mem_nil, or_false] at hc
    rcases hc with h' | h' <;> subst h' <;> rfl

theorem balance_genesis_witness_is_one_hot (channelId salt : Nat) :
    (Balance.SwitchBoardWitness.filled ⟨some (channelId, salt), none, none, none⟩) = 1 := rfl

theorem balance_leaf_witness_is_one_hot (m : Balance.Mode) (p : Proof)
    (h : m ≠ .initial) : (Balance.switchBoardWitness m p).filled = 1 := by
  cases m with
  | initial => exact absurd rfl h
  | receiveTransfer => rfl
  | receiveDeposit => rfl
  | sendTx => rfl

theorem balance_leaf_failure_skips_switch_board_and_balance (e : Balance.Env)
    (m : Balance.Mode) (lw : Balance.LeafWitness) (msg : String)
    (h : e.proveLeaf m lw = .error msg) :
    Balance.proveLeafRun e m lw = ([.proveLeaf m lw], .error (Balance.leafError m msg)) := by
  simp only [Balance.proveLeafRun, h]

theorem balance_leaf_error_is_per_mode (msg : String) :
    Balance.leafError .receiveTransfer msg = .receiveTransferCircuit msg
      ∧ Balance.leafError .receiveDeposit msg = .receiveDepositCircuit msg
      ∧ Balance.leafError .sendTx msg = .sendTxCircuit msg := ⟨rfl, rfl, rfl⟩

theorem balance_switch_board_receives_balance_verifier_data (e : Balance.Env)
    (w : Balance.SwitchBoardWitness) :
    (Balance.finish e w).1.head? = some (.proveSwitchBoard e.balanceVd w) := by
  simp only [Balance.finish]
  split
  · rfl
  · split <;> rfl

theorem balance_switch_board_failure_skips_balance_circuit (e : Balance.Env)
    (w : Balance.SwitchBoardWitness) (m : String)
    (h : e.proveSwitchBoard e.balanceVd w = .error m) :
    Balance.finish e w = ([.proveSwitchBoard e.balanceVd w], .error (.switchBoardCircuit m)) := by
  simp only [Balance.finish, h]

theorem balance_result_is_balance_circuit_output (e : Balance.Env)
    (w : Balance.SwitchBoardWitness) (p : Proof) (h : (Balance.finish e w).2 = .ok p) :
    ∃ sp, e.proveSwitchBoard e.balanceVd w = .ok sp ∧ e.proveBalance sp = .ok p := by
  simp only [Balance.finish] at h
  split at h
  · exact absurd h (by simp)
  · next sp hs =>
    split at h
    · exact absurd h (by simp)
    · next q hq =>
      refine ⟨sp, hs, ?_⟩
      have : q = p := by simpa using h
      rw [hq, this]

theorem balance_leaf_proof_precedes_switch_board (e : Balance.Env) (m : Balance.Mode)
    (lw : Balance.LeafWitness) (p : Proof) (h : e.proveLeaf m lw = .ok p) :
    (Balance.proveLeafRun e m lw).1
      = .proveLeaf m lw :: (Balance.finish e (Balance.switchBoardWitness m p)).1 := by
  simp only [Balance.proveLeafRun, h]

theorem balance_entry_points_differ_only_in_mode (e : Balance.Env) (lw : Balance.LeafWitness) :
    Balance.proveReceiveTransferRun e lw = Balance.proveLeafRun e .receiveTransfer lw
      ∧ Balance.proveReceiveDepositRun e lw = Balance.proveLeafRun e .receiveDeposit lw
      ∧ Balance.proveSendTxRun e lw = Balance.proveLeafRun e .sendTx lw := ⟨rfl, rfl, rfl⟩

theorem balance_codec_slot_order_round_trips :
    Balance.serializeOrder = Balance.deserializeOrder := rfl

namespace Balance

def exampleEnv : Env where
  balanceVd := 500
  proveLeaf := fun _ lw => .ok ⟨"leaf", [lw.word]⟩
  proveSwitchBoard := fun vd _ => .ok ⟨"switch_board", [vd]⟩
  proveBalance := fun p => .ok ⟨"balance", p.pis⟩

end Balance

theorem balance_example_initial_succeeds :
    (Balance.proveInitialRun Balance.exampleEnv 7 9).2 = .ok ⟨"balance", [500]⟩ := rfl

theorem balance_example_initial_makes_two_calls :
    (Balance.proveInitialRun Balance.exampleEnv 7 9).1.length = 2 := rfl

theorem balance_example_send_tx_makes_three_calls :
    (Balance.proveSendTxRun Balance.exampleEnv ⟨3⟩).1.length = 3 := rfl

/-! ## `withdrawal_processor.rs`

Two entry points. `prove_step` folds one single-withdrawal proof into the
withdrawal chain; `prove_final` wraps a chain proof together with the prover
address and the extended public state. Neither verifies its input proof
natively. -/

namespace Withdrawal

/-- An Ethereum address, opaque. -/
abbrev Address := Nat

/-- `WithdrawalStepWitness`, opaque apart from the chained proof. -/
structure StepWitness where
  prevChainProof : Option Proof
  singleWithdrawalProof : Proof
  payload : Nat
  deriving DecidableEq, Repr

/-- `WithdrawalProcessorError`. -/
inductive Error where
  | withdrawalStepCircuit (message : String)
  | withdrawalChainCircuit (message : String)
  | withdrawalCircuit (message : String)
  deriving DecidableEq, Repr

inductive Call where
  | proveWithdrawalStep (chainVd : VerifierData) (witness : StepWitness)
  | proveWithdrawalChain (stepProof : Proof)
  | proveWithdrawal (chainProof : Proof) (prover : Address)
      (extPublicState : BlockChain.ExtPublicState)
  deriving DecidableEq, Repr

inductive Artifact where
  | chainCd | stepCircuit | stepVd | chainCircuit | chainVd | withdrawalCircuit | withdrawalVd
  deriving DecidableEq, Repr

/-- `new` also consumes an externally supplied `single_withdrawal_vd`; that is a
parameter, not a produced artifact. -/
def buildPlan : List (BuildStep Artifact) :=
  [ ⟨.chainCd, []⟩,
    ⟨.stepCircuit, [.chainCd]⟩,
    ⟨.stepVd, [.stepCircuit]⟩,
    ⟨.chainCircuit, [.chainCd, .stepVd]⟩,
    ⟨.chainVd, [.chainCircuit]⟩,
    ⟨.withdrawalCircuit, [.chainVd]⟩,
    ⟨.withdrawalVd, [.withdrawalCircuit]⟩ ]

structure Env where
  chainVd : VerifierData
  proveStepCircuit : VerifierData → StepWitness → Except String Proof
  proveChainCircuit : Proof → Except String Proof
  proveWithdrawalCircuit : Proof → Address → BlockChain.ExtPublicState → Except String Proof

def proveStepRun (e : Env) (w : StepWitness) : List Call × Except Error Proof :=
  match e.proveStepCircuit e.chainVd w with
  | .error m => ([.proveWithdrawalStep e.chainVd w], .error (.withdrawalStepCircuit m))
  | .ok sp =>
      match e.proveChainCircuit sp with
      | .error m =>
          ([.proveWithdrawalStep e.chainVd w, .proveWithdrawalChain sp],
           .error (.withdrawalChainCircuit m))
      | .ok cp => ([.proveWithdrawalStep e.chainVd w, .proveWithdrawalChain sp], .ok cp)

def proveFinalRun (e : Env) (chainProof : Proof) (prover : Address)
    (ext : BlockChain.ExtPublicState) : List Call × Except Error Proof :=
  match e.proveWithdrawalCircuit chainProof prover ext with
  | .error m => ([.proveWithdrawal chainProof prover ext], .error (.withdrawalCircuit m))
  | .ok p => ([.proveWithdrawal chainProof prover ext], .ok p)

end Withdrawal

theorem withdrawal_build_plan_is_ordered :
    buildOrdered Withdrawal.buildPlan [] = true := by decide

theorem withdrawal_circuit_binds_chain_verifier_data :
    Withdrawal.buildPlan[5]?.map BuildStep.requires
      = some [Withdrawal.Artifact.chainVd] := by decide

theorem withdrawal_prove_step_uses_chain_verifier_data (e : Withdrawal.Env)
    (w : Withdrawal.StepWitness) :
    (Withdrawal.proveStepRun e w).1.head? = some (.proveWithdrawalStep e.chainVd w) := by
  simp only [Withdrawal.proveStepRun]
  split
  · rfl
  · split <;> rfl

theorem withdrawal_step_failure_skips_chain_circuit (e : Withdrawal.Env)
    (w : Withdrawal.StepWitness) (m : String)
    (h : e.proveStepCircuit e.chainVd w = .error m) :
    Withdrawal.proveStepRun e w
      = ([.proveWithdrawalStep e.chainVd w], .error (.withdrawalStepCircuit m)) := by
  simp only [Withdrawal.proveStepRun, h]

theorem withdrawal_prove_step_wraps_step_proof (e : Withdrawal.Env)
    (w : Withdrawal.StepWitness) (p : Proof) (h : (Withdrawal.proveStepRun e w).2 = .ok p) :
    ∃ sp, e.proveStepCircuit e.chainVd w = .ok sp ∧ e.proveChainCircuit sp = .ok p := by
  simp only [Withdrawal.proveStepRun] at h
  split at h
  · exact absurd h (by simp)
  · next sp hs =>
    split at h
    · exact absurd h (by simp)
    · next q hq =>
      refine ⟨sp, hs, ?_⟩
      have : q = p := by simpa using h
      rw [hq, this]

/-- `prove_final` makes exactly one call: it does NOT verify the chain proof it
is handed, and it does not re-derive the extended public state. -/
theorem withdrawal_prove_final_makes_one_call (e : Withdrawal.Env) (cp : Proof)
    (prover : Withdrawal.Address) (ext : BlockChain.ExtPublicState) :
    (Withdrawal.proveFinalRun e cp prover ext).1 = [.proveWithdrawal cp prover ext] := by
  simp only [Withdrawal.proveFinalRun]
  split <;> rfl

theorem withdrawal_prove_final_threads_prover_and_ext_state (e : Withdrawal.Env) (cp : Proof)
    (prover : Withdrawal.Address) (ext : BlockChain.ExtPublicState) (p : Proof)
    (h : (Withdrawal.proveFinalRun e cp prover ext).2 = .ok p) :
    e.proveWithdrawalCircuit cp prover ext = .ok p := by
  simp only [Withdrawal.proveFinalRun] at h
  split at h
  · exact absurd h (by simp)
  · next q hq =>
    have : q = p := by simpa using h
    rw [hq, this]

namespace Withdrawal

def exampleEnv : Env where
  chainVd := 700
  proveStepCircuit := fun vd _ => .ok ⟨"withdrawal_step", [vd]⟩
  proveChainCircuit := fun p => .ok ⟨"withdrawal_chain", p.pis⟩
  proveWithdrawalCircuit := fun p a _ => .ok ⟨"withdrawal", p.pis ++ [a]⟩

def exampleWitness : StepWitness := ⟨none, ⟨"single_withdrawal", []⟩, 0⟩

end Withdrawal

theorem withdrawal_example_step_succeeds :
    (Withdrawal.proveStepRun Withdrawal.exampleEnv Withdrawal.exampleWitness).2
      = .ok ⟨"withdrawal_chain", [700]⟩ := rfl

theorem withdrawal_example_final_binds_prover :
    (Withdrawal.proveFinalRun Withdrawal.exampleEnv ⟨"withdrawal_chain", [700]⟩ 42
        BlockChain.exampleState).2 = .ok ⟨"withdrawal", [700, 42]⟩ := rfl

end Zkp.Implementation.Processors
