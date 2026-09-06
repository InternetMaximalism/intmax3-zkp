import Std

/-!
# CloseFundingMaterializer: executable source-level projection

Source: contracts/src/CloseFundingMaterializer.sol, all 562 physical lines.
The line map classifies executable legacy code separately from deployed tombstones.
This is a manual translation, NOT a Solidity/EVM refinement certificate.

Nat represents canonical unsigned ABI values. Runtime correspondences require
uint32/64/256/address widths at the ABI/getter boundary; checked arithmetic is
explicit where the source performs it. Getter results may fail at their actual
read sites. Static getter coherence, ABI decoding, gas, hash/encoding semantics,
verifier soundness and transaction rollback are explicit dependency boundaries.
No external observation asserts the desired conservation or one-shot theorem.

The Rollup's actual creditChannelExit/_credit*Escrow arithmetic is expanded here:
no token transfer occurs during materialization, only escrow-to-pending credit.
The materializer latch and all credits commit together through `commit`.
This models EVM rollback; it does not prove EVM semantics or storage isolation.
Receipts are keyed by exact domain-separated preimages through hash oracles.
Receipt preimage uniqueness requires collision resistance/faithful ABI encoding;
the storage theorems do not silently assume hash injectivity.

The source comment about avoiding a second verification is not normative:
`materializeSignedHead` below invokes the verifier again, as the source does.
`lastPostedBlock` can decrease on rollback: only receipt anchor maxima are
monotone, and current-anchor usability is rechecked against the live journal.
-/

namespace Zkp.Implementation.CloseFunding

abbrev Address := Nat
abbrev Hash := Nat
abbrev Bytes := List UInt8
abbrev Channel := Nat
abbrev Token := Nat

def u32Limit : Nat := 2 ^ 32
def u63Limit : Nat := 2 ^ 63
def u64Limit : Nat := 2 ^ 64
def u256Limit : Nat := 2 ^ 256
def maxChannelTokens : Nat := 10
def backingStatementDomain : Nat := 0x494d4241
def backingProofDomain : Nat := 0x494d4250

inductive Error where
  | revert (name : String) (arguments : List Nat := [])
  | panic (kind : String)
  | external (label : String)
  deriving DecidableEq, Repr

abbrev Result := Except Error

@[simp] theorem result_bind_ok {α β : Type} (x : α) (f : α → Result β) :
    ((Except.ok x : Result α) >>= f) = f x := rfl

@[simp] theorem result_bind_error {α β : Type} (error : Error) (f : α → Result β) :
    ((Except.error error : Result α) >>= f) = .error error := rfl

@[simp] theorem result_pure {α : Type} (x : α) : (pure x : Result α) = .ok x := rfl

def require (condition : Bool) (error : Error) : Result Unit :=
  if condition then .ok () else .error error

def put {α : Type} (f : Nat → α) (key : Nat) (value : α) : Nat → α :=
  fun k => if k = key then value else f k

inductive Status where
  | active | closePending | closed
  deriving DecidableEq, Repr

/-- Every field is a separate possibly reverting external getter. -/
structure ManagerView where
  channelId : Result Channel
  registry : Result Address
  materializer : Result Address
  generation : Result Nat
  status : Result Status
  closeDigest : Result Hash
  stateRoot : Result Hash
  settledChain : Result Hash
  tokenFundsDigest : Result Hash
  tokenCount : Result Nat
  tokenAt : Nat → Result Token
  amountAt : Token → Result Nat

structure VerifierView where
  allowedChainId : Result Nat
  core : Result Address

structure StatementKeyInput where
  domain : Nat
  chainId : Nat
  deployment : Address
  rollup : Address
  manager : Address
  channelId : Channel
  settledChain : Hash
  tokenFundsDigest : Hash
  deriving DecidableEq, Repr

structure ProofKeyInput where
  domain : Nat
  chainId : Nat
  deployment : Address
  rollup : Address
  manager : Address
  proofHash : Hash
  deriving DecidableEq, Repr

/-- Hash functions stand for keccak256(abi.encode(...)) and keccak256(bytes).
The input records expose the exact ordered domain fields, not collision freedom. -/
structure Environment where
  chainId : Nat
  self : Address
  rollup : Address
  backingVerifier : Address
  codeLength : Address → Nat
  verifier : Address → VerifierView
  manager : Address → ManagerView
  channelMemberSet : Channel → Result Hash
  blockNumber : Result Nat
  latestFinalized : Result Nat
  isFinalizedRoot : Hash → Result Bool
  verifyCompact : Bytes → Result (List Nat)
  hashStatement : StatementKeyInput → Hash
  hashProofKey : ProofKeyInput → Hash
  hashBytes : Bytes → Hash
  rollupDeploymentChain : Nat
  installedMaterializer : Address

structure Immutables where
  rollup : Address
  backingVerifier : Address
  deriving DecidableEq, Repr

def requirePinnedVerifier (e : Environment) (v : Address) : Result Unit := do
  require (e.codeLength v != 0) (.revert "InvalidBackingVerifier" [v])
  let chain ← (e.verifier v).allowedChainId.mapError
    (fun _ => .revert "InvalidBackingVerifier" [v])
  require (chain == e.chainId) (.revert "BackingVerifierChainMismatch" [v, e.chainId, chain])
  let core ← (e.verifier v).core.mapError (fun _ => .revert "InvalidBackingVerifier" [v])
  require (e.codeLength core != 0) (.revert "InvalidBackingVerifier" [v])
  let coreChain ← (e.verifier core).allowedChainId.mapError
    (fun _ => .revert "InvalidBackingVerifier" [core])
  require (coreChain == e.chainId)
    (.revert "BackingVerifierChainMismatch" [core, e.chainId, coreChain])

def constructor (e : Environment) : Result Immutables := do
  require (e.codeLength e.rollup != 0) (.revert "InvalidRollup")
  requirePinnedVerifier e e.backingVerifier
  pure ⟨e.rollup, e.backingVerifier⟩

structure State where
  managerOfChannel : Channel → Address
  frozenGeneration : Channel → Nat
  lastPostedBlock : Channel → Nat
  materializedChannelExit : Channel → Hash
  anchorPlusOne : Hash → Nat
  attestedProof : Hash → Bool
  postedChannel : Nat → Channel
  previousChannelBlock : Nat → Nat

def empty : State :=
  ⟨fun _ => 0, fun _ => 0, fun _ => 0, fun _ => 0,
   fun _ => 0, fun _ => false, fun _ => 0, fun _ => 0⟩

inductive Event where
  | bound (channel : Channel) (manager : Address)
  | frozen (channel generation lastPost : Nat)
  | unfrozen (channel generation : Nat)
  | attested (channel manager key root anchor proofId : Nat)
  | materialized (channel manager digest tokenCount : Nat)
  deriving DecidableEq, Repr

abbrev Update := State × List Event

def onlyRollup (e : Environment) (caller : Address) : Result Unit :=
  require (caller == e.rollup) (.revert "OnlyRollup")

def bindState (s : State) (channel : Channel) (manager block : Nat) : State :=
  { s with managerOfChannel := put s.managerOfChannel channel manager
           lastPostedBlock := put s.lastPostedBlock channel block }

def bindManager (e : Environment) (s : State) (caller manager : Address) : Result Update := do
  onlyRollup e caller
  require (e.codeLength manager != 0) (.revert "InvalidManager")
  let channel ← (e.manager manager).channelId
  if channel == 0 then throw (.revert "InvalidManager")
  let memberSet ← e.channelMemberSet channel
  require (memberSet != 0) (.revert "InvalidManager")
  let registry ← (e.manager manager).registry
  require (registry == e.rollup) (.revert "ManagerRollupMismatch")
  let satellite ← (e.manager manager).materializer
  require (satellite == e.self) (.revert "ManagerMaterializerMismatch")
  let incumbent := s.managerOfChannel channel
  require (incumbent == 0 || incumbent == manager) (.revert "ManagerAlreadyBound" [channel])
  let block ← e.blockNumber
  let finalized ← e.latestFinalized
  require (block == finalized) (.revert "BindWithUnfinalizedHead")
  if incumbent == 0 then
    let bindingBlock ← e.blockNumber
    pure (bindState s channel manager bindingBlock, [.bound channel manager])
  else pure (s, [])

def freezeState (s : State) (channel generation : Nat) : State :=
  { s with frozenGeneration := put s.frozenGeneration channel generation }

def freezeFromManager (e : Environment) (s : State) (caller : Address)
    (channel generation : Nat) : Result Update := do
  require (s.managerOfChannel channel == caller) (.revert "NotBoundManager")
  require (s.materializedChannelExit channel == 0) (.revert "ChannelAlreadyExited")
  require (s.frozenGeneration channel == 0) (.revert "ChannelExitAlreadyFrozen")
  let actualChannel ← (e.manager caller).channelId
  require (actualChannel == channel) (.revert "ChannelExitGenerationMismatch")
  let actualGeneration ← (e.manager caller).generation
  require (actualGeneration == generation && generation != 0) (.revert "ChannelExitGenerationMismatch")
  let status ← (e.manager caller).status
  require (status == .closePending) (.revert "ChannelExitGenerationMismatch")
  pure (freezeState s channel generation, [.frozen channel generation (s.lastPostedBlock channel)])

def unfreezeFromManager (s : State) (caller : Address) (channel generation : Nat) : Result Update := do
  require (s.managerOfChannel channel == caller) (.revert "NotBoundManager")
  let frozen := s.frozenGeneration channel
  require (frozen != 0) (.revert "ChannelExitNotFrozen")
  require (frozen == generation) (.revert "ChannelExitGenerationMismatch")
  require (s.materializedChannelExit channel == 0) (.revert "ChannelAlreadyExited")
  pure (freezeState s channel 0, [.unfrozen channel generation])

def recordPostState (s : State) (channel block : Nat) : State :=
  { s with postedChannel := put s.postedChannel block channel
           previousChannelBlock := put s.previousChannelBlock block (s.lastPostedBlock channel)
           lastPostedBlock := put s.lastPostedBlock channel block }

def recordPost (e : Environment) (s : State) (caller : Address) (channel block : Nat) : Result Update := do
  onlyRollup e caller
  if s.managerOfChannel channel == 0 then pure (s, []) else
    require (s.materializedChannelExit channel == 0) (.revert "ChannelAlreadyExited")
    require (s.frozenGeneration channel == 0) (.revert "ChannelExitAlreadyFrozen")
    pure (recordPostState s channel block, [])

def rollbackState (s : State) (block channel : Nat) : State :=
  { s with lastPostedBlock := put s.lastPostedBlock channel (s.previousChannelBlock block)
           postedChannel := put s.postedChannel block 0
           previousChannelBlock := put s.previousChannelBlock block 0 }

def rollbackPost (e : Environment) (s : State) (caller : Address) (block : Nat) : Result Update := do
  onlyRollup e caller
  let channel := s.postedChannel block
  if channel == 0 then pure (s, []) else
    require (s.lastPostedBlock channel == block) (.revert "ChannelExitStatementMismatch")
    pure (rollbackState s block channel, [])

structure BackingStatement where
  settledChain : Hash
  tokenFundsDigest : Hash
  backingRoot : Hash
  anchor : Nat
  deriving DecidableEq, Repr

/-- Indexed memory access retains the Solidity bounds-revert boundary. -/
def limbAt (pi : List Nat) (i : Nat) : Result Nat :=
  match pi[i]? with
  | none => .error (.panic "array bounds")
  | some x => .ok x

def limbsMatchLoop (limbs : List Nat) (offset value : Nat) : Nat → Nat → Result Bool
  | 0, _ => pure true
  | n + 1, i => do
    let limb ← limbAt limbs (offset + i)
    if limb != (value / 2 ^ (224 - 32 * i)) % u32Limit then pure false
    else limbsMatchLoop limbs offset value n (i + 1)

def limbsMatch (limbs : List Nat) (offset value : Nat) : Result Bool :=
  limbsMatchLoop limbs offset value 8 0

def limbsToBytes32Loop (limbs : List Nat) (offset : Nat) : Nat → Nat → Nat → Result Nat
  | 0, _, v => pure v
  | n + 1, i, v => do
    let limb ← limbAt limbs (offset + i)
    limbsToBytes32Loop limbs offset n (i + 1) ((Nat.shiftLeft v 32 ||| limb) % u256Limit)

def limbsToBytes32 (limbs : List Nat) (offset : Nat) : Result Hash :=
  limbsToBytes32Loop limbs offset 8 0 0

def checkU32Limbs (pi : List Nat) : Nat → Nat → Result Unit
  | 0, _ => pure ()
  | n + 1, i => do
    let limb ← limbAt pi i
    require (limb < u32Limit) (.revert "BackingPublicInputsMismatch")
    checkU32Limbs pi n (i + 1)

def validateBackingPublicInputs (e : Environment) (s : State) (manager : Address)
    (pi : List Nat) : Result BackingStatement := do
  require (pi.length == 26) (.revert "BackingPublicInputsMismatch")
  checkU32Limbs pi 25 0
  let anchor ← limbAt pi 25
  require (anchor < u63Limit) (.revert "BackingPublicInputsMismatch")
  let channel ← (e.manager manager).channelId
  require (s.managerOfChannel channel == manager) (.revert "NotBoundManager")
  let piChannel ← limbAt pi 0
  require (piChannel == channel) (.revert "BackingPublicInputsMismatch")
  let settled ← limbsToBytes32 pi 1
  let funds ← limbsToBytes32 pi 9
  let root ← limbsToBytes32 pi 17
  let finalized ← e.isFinalizedRoot root
  require finalized (.revert "BackingPublicInputsMismatch")
  let lastFinalized ← e.latestFinalized
  require (anchor ≤ lastFinalized) (.revert "ChannelExitHasUnfinalizedBlocks")
  pure ⟨settled, funds, root, anchor⟩

def backingStatementInput (e : Environment) (manager channel settled funds : Nat) : StatementKeyInput :=
  ⟨backingStatementDomain, e.chainId, e.self, e.rollup, manager, channel, settled, funds⟩

def backingStatementKey (e : Environment) (manager channel settled funds : Nat) : Hash :=
  e.hashStatement (backingStatementInput e manager channel settled funds)

def backingProofInput (e : Environment) (manager : Address) (proof : Bytes) : ProofKeyInput :=
  ⟨backingProofDomain, e.chainId, e.self, e.rollup, manager, e.hashBytes proof⟩

def backingProofId (e : Environment) (manager : Address) (proof : Bytes) : Hash :=
  e.hashProofKey (backingProofInput e manager proof)

def verifyBackingProof (e : Environment) (proof : Bytes) : Result (List Nat) :=
  (e.verifyCompact proof).mapError (fun _ => .revert "BackingProofInvalid")

structure Attestation where
  channel : Channel
  manager : Address
  statement : BackingStatement
  key : Hash
  proofId : Hash
  deriving DecidableEq, Repr

def prepareAttestation (e : Environment) (s : State) (manager : Address)
    (proof : Bytes) : Result Attestation := do
  let pi ← verifyBackingProof e proof
  let statement ← validateBackingPublicInputs e s manager pi
  let channel ← (e.manager manager).channelId
  require (statement.anchor + 1 < u64Limit) (.panic "uint64 overflow")
  pure ⟨channel, manager, statement,
    backingStatementKey e manager channel statement.settledChain statement.tokenFundsDigest,
    backingProofId e manager proof⟩

def attestState (s : State) (a : Attestation) : State :=
  { s with anchorPlusOne := put s.anchorPlusOne a.key (max (a.statement.anchor + 1) (s.anchorPlusOne a.key))
           attestedProof := put s.attestedProof a.proofId true }

def attestSignedHeadBacking (e : Environment) (s : State) (manager : Address)
    (proof : Bytes) : Result Update := do
  let a ← prepareAttestation e s manager proof
  pure (attestState s a, if s.attestedProof a.proofId then [] else
    [.attested a.channel a.manager a.key a.statement.backingRoot a.statement.anchor a.proofId])

def hasSignedHeadBacking (e : Environment) (s : State)
    (manager channel settled funds : Nat) (requireCurrent : Bool) : Bool :=
  if s.managerOfChannel channel != manager then false else
    let a := s.anchorPlusOne (backingStatementKey e manager channel settled funds)
    a != 0 && (!requireCurrent || decide (s.lastPostedBlock channel ≤ a - 1))

def requireSignedHeadBacking (e : Environment) (s : State)
    (caller channel settled funds : Nat) : Result Unit := do
  let status ← (e.manager caller).status
  require (hasSignedHeadBacking e s caller channel settled funds (status != .active))
    (.revert "BackingProofNotAttested")

structure Credit where
  token : Token
  amount : Nat
  deriving DecidableEq, Repr

/-- Exact nested duplicate scan, followed by the Manager's amount getter.
Fuel is the already range-checked tokenCount; no caller supplies token amounts. -/
def readVector (m : ManagerView) : Nat → Nat → List Token → Result (List Credit)
  | 0, _, _ => pure []
  | remaining + 1, i, seen => do
    let token ← m.tokenAt i
    require (!seen.contains token) (.revert "ChannelExitDuplicateToken" [token])
    let amount ← m.amountAt token
    let tail ← readVector m remaining (i + 1) (seen ++ [token])
    pure (⟨token, amount⟩ :: tail)

structure MaterializationPlan where
  channel : Channel
  manager : Address
  digest : Hash
  tokenCount : Nat
  credits : List Credit
  deriving DecidableEq, Repr

def prepareMaterialization (e : Environment) (s : State) (manager : Address)
    (anchor : Nat) : Result MaterializationPlan := do
  let m := e.manager manager
  let channel ← m.channelId
  require (s.managerOfChannel channel == manager) (.revert "NotBoundManager")
  let generation := s.frozenGeneration channel
  require (generation != 0) (.revert "ChannelExitNotFrozen")
  require (s.materializedChannelExit channel == 0) (.revert "ChannelAlreadyExited")
  let status ← m.status
  require (status == .closed) (.revert "ChannelExitManagerNotClosed")
  let managerGeneration ← m.generation
  require (managerGeneration == generation) (.revert "ChannelExitGenerationMismatch")
  let digest ← m.closeDigest
  let stateRoot ← m.stateRoot
  require (digest != 0) (.revert "ChannelExitStatementMismatch")
  let rootFinalized ← e.isFinalizedRoot stateRoot
  require rootFinalized (.revert "ChannelExitStatementMismatch")
  let finalized ← e.latestFinalized
  require (anchor ≤ finalized && s.lastPostedBlock channel ≤ anchor)
    (.revert "ChannelExitHasUnfinalizedBlocks")
  let count ← m.tokenCount
  require (count != 0 && count ≤ maxChannelTokens) (.revert "ChannelExitTokenCountOutOfRange")
  let vector ← readVector m count 0 []
  pure ⟨channel, manager, digest, count, vector⟩

def prepareSignedHead (e : Environment) (s : State) (manager : Address)
    (proof : Bytes) : Result MaterializationPlan := do
  let pi ← verifyBackingProof e proof
  let statement ← validateBackingPublicInputs e s manager pi
  require (s.attestedProof (backingProofId e manager proof)) (.revert "BackingProofNotAttested")
  let settled ← (e.manager manager).settledChain
  require (statement.settledChain == settled) (.revert "BackingPublicInputsMismatch")
  let funds ← (e.manager manager).tokenFundsDigest
  require (statement.tokenFundsDigest == funds) (.revert "BackingPublicInputsMismatch")
  prepareMaterialization e s manager statement.anchor

structure Ledger where
  escrow : Token → Nat
  pending : Token → Address → Nat

def creditState (l : Ledger) (manager : Address) (c : Credit) : Ledger :=
  { escrow := put l.escrow c.token (l.escrow c.token - c.amount)
    pending := put l.pending c.token
      (put (l.pending c.token) manager (l.pending c.token manager + c.amount)) }

/-- Direct Rollup interface expansion. Token 0 selects totalEscrowed/native
pendingWithdrawals; nonzero tokens select escrowedByToken/pendingTokenWithdrawals. -/
def creditChannelExit (e : Environment) (l : Ledger) (manager : Address) (c : Credit) : Result Ledger := do
  require (e.chainId == e.rollupDeploymentChain) (.revert "ReleaseRuntimeUnavailable")
  require (e.self == e.installedMaterializer) (.revert "InvalidChannelExitManager")
  require (c.amount ≤ l.escrow c.token) (.panic "uint256 underflow")
  require (l.pending c.token manager + c.amount < u256Limit) (.panic "uint256 overflow")
  pure (creditState l manager c)

def creditVector (e : Environment) (manager : Address) : Ledger → List Credit → Result Ledger
  | l, [] => pure l
  | l, c :: cs => do
    let next ← if c.amount == 0 then pure l else creditChannelExit e l manager c
    creditVector e manager next cs

def latchState (s : State) (p : MaterializationPlan) : State :=
  { s with materializedChannelExit := put s.materializedChannelExit p.channel p.digest }

structure World where
  storage : State
  ledger : Ledger

def materializeSignedHead (e : Environment) (w : World) (manager : Address)
    (proof : Bytes) : Result (World × List Event) := do
  let p ← prepareSignedHead e w.storage manager proof
  let latched := latchState w.storage p
  let credited ← creditVector e manager w.ledger p.credits
  pure (⟨latched, credited⟩, [.materialized p.channel manager p.digest p.tokenCount])

/-- A result error restores all tracked writes and all emitted logs. -/
def commit {α : Type} (before : α) (result : Result (α × List Event)) : α × List Event :=
  match result with
  | .ok after => after
  | .error _ => (before, [])

def materializeNative : Result Unit := .error (.revert "CooperativeCloseFundingDeprecated")
def materializeERC20 : Result Unit := .error (.revert "CooperativeCloseFundingDeprecated")

/-! ## Retired abstract contract: executable bodies, not deployed tombstones
Its external authorization/withdrawal effects are explicit dependencies. Against
the current Manager every authorizeCloseFunding call reverts; the abstract
historical body is nevertheless translated rather than erased as dead prose.
-/

structure Withdrawal where
  recipient : Address
  token : Token
  amount : Nat
  auxData : Hash
  deriving DecidableEq, Repr

def legacyConstructor (e : Environment) : Result Address := do
  require (e.codeLength e.rollup != 0) (.revert "InvalidRollup")
  pure e.rollup

def legacyExpectedCount (m : ManagerView) (nativeLane : Bool) : Nat → Nat → Result Nat
  | 0, _ => pure 0
  | n + 1, i => do
    let token ← m.tokenAt i
    let amount ← m.amountAt token
    let rest ← legacyExpectedCount m nativeLane n (i + 1)
    if amount != 0 && ((token == 0) == nativeLane) then
      if rest + 1 < u256Limit then pure (rest + 1) else throw (.panic "uint256 overflow")
    else pure rest

def legacyFindSlot (m : ManagerView) (nativeLane : Bool) (w : Withdrawal)
    (matched : Nat → Bool) : Nat → Nat → Result (Option Nat)
  | 0, _ => pure none
  | n + 1, i => do
    let token ← m.tokenAt i
    let amount ← m.amountAt token
    if amount == 0 || ((token == 0) != nativeLane) || token != w.token then
      legacyFindSlot m nativeLane w matched n (i + 1)
    else
      require (i < maxChannelTokens) (.panic "array bounds")
      require (!matched i) (.revert "DuplicateFundingToken" [token])
      require (w.amount == amount) (.revert "FundingAmountMismatch" [token, amount, w.amount])
      pure (some i)

def legacyValidateWithdrawals (m : ManagerView) (manager : Address) (nativeLane : Bool)
    (count : Nat) : List Withdrawal → Nat → (Nat → Bool) → Hash → Result Hash
  | [], _, _, aux => pure aux
  | w :: ws, i, matched, aux => do
    require (w.recipient == manager) (.revert "FundingRecipientMismatch" [i])
    require ((w.token == 0) == nativeLane) (.revert "FundingAssetClassMismatch" [i])
    let found ← legacyFindSlot m nativeLane w matched count 0
    match found with
    | none => throw (.revert "FundingTokenNotExpected" [w.token])
    | some slot =>
      if i == 0 then
        legacyValidateWithdrawals m manager nativeLane count ws (i + 1) (put matched slot true) w.auxData
      else
        require (w.auxData == aux) (.revert "FundingAuxDataMismatch" [i])
        legacyValidateWithdrawals m manager nativeLane count ws (i + 1) (put matched slot true) aux

def legacyValidateCompleteLane (e : Environment) (manager : Address)
    (withdrawals : List Withdrawal) (nativeLane : Bool) : Result Hash := do
  let registry ← (e.manager manager).registry
  require (registry == e.rollup) (.revert "ManagerRollupMismatch")
  let satellite ← (e.manager manager).materializer
  require (satellite == e.self) (.revert "ManagerMaterializerMismatch")
  let count ← (e.manager manager).tokenCount
  let expected ← legacyExpectedCount (e.manager manager) nativeLane count 0
  require (expected != 0) (.revert "EmptyFundingLane")
  require (withdrawals.length == expected) (.revert "FundingLaneLengthMismatch" [expected, withdrawals.length])
  legacyValidateWithdrawals (e.manager manager) manager nativeLane count withdrawals 0 (fun _ => false) 0

structure LegacyCalls where
  authorize : Address → Token → Hash → Result Unit
  withdraw : Bool → List Withdrawal → Address → Bytes → Result Unit
  withdrawalSetHash : List Withdrawal → Hash

def legacyAuthorizeAll (calls : LegacyCalls) (manager : Address) : List Withdrawal → Result Unit
  | [] => pure ()
  | w :: ws => do
    calls.authorize manager w.token w.auxData
    legacyAuthorizeAll calls manager ws

def legacyMaterialize (e : Environment) (calls : LegacyCalls) (manager : Address)
    (withdrawals : List Withdrawal) (prover : Address) (proof : Bytes) (nativeLane : Bool) :
    Result (Address × Nat × Hash × Hash) := do
  let aux ← legacyValidateCompleteLane e manager withdrawals nativeLane
  legacyAuthorizeAll calls manager withdrawals
  calls.withdraw nativeLane withdrawals prover proof
  pure (manager, if nativeLane then 0 else 1, aux, calls.withdrawalSetHash withdrawals)

def legacyMaterializeNative (e : Environment) (calls : LegacyCalls) (manager : Address)
    (withdrawals : List Withdrawal) (prover : Address) (proof : Bytes) :=
  legacyMaterialize e calls manager withdrawals prover proof true

def legacyMaterializeERC20 (e : Environment) (calls : LegacyCalls) (manager : Address)
    (withdrawals : List Withdrawal) (prover : Address) (proof : Bytes) :=
  legacyMaterialize e calls manager withdrawals prover proof false

/-! ## Local storage, parsing, authority, replay and conservation theorems -/

theorem commit_error_atomic {α : Type} (s : α) (error : Error) :
    commit s (.error error) = (s, []) := rfl

theorem retired_native_rejects :
    materializeNative = .error (.revert "CooperativeCloseFundingDeprecated") := rfl

theorem retired_erc20_rejects :
    materializeERC20 = .error (.revert "CooperativeCloseFundingDeprecated") := rfl

theorem statement_key_complete_domain (e : Environment) (m c tx funds : Nat) :
    backingStatementInput e m c tx funds =
      ⟨backingStatementDomain, e.chainId, e.self, e.rollup, m, c, tx, funds⟩ := rfl

theorem proof_key_exact_bytes_domain (e : Environment) (m : Address) (proof : Bytes) :
    backingProofInput e m proof =
      ⟨backingProofDomain, e.chainId, e.self, e.rollup, m, e.hashBytes proof⟩ := rfl

theorem verifier_failure_rejected {e : Environment} {proof : Bytes} {error : Error}
    (h : e.verifyCompact proof = .error error) :
    verifyBackingProof e proof = .error (.revert "BackingProofInvalid") := by
  simp [verifyBackingProof, h, Except.mapError]

theorem attest_anchor_monotone (s : State) (a : Attestation) (key : Hash) :
    s.anchorPlusOne key ≤ (attestState s a).anchorPlusOne key := by
  simp only [attestState, put]
  split
  · subst key; exact Nat.le_max_right _ _
  · exact Nat.le_refl _

theorem attest_anchor_exact_max (s : State) (a : Attestation) :
    (attestState s a).anchorPlusOne a.key =
      max (a.statement.anchor + 1) (s.anchorPlusOne a.key) := by simp [attestState, put]

theorem attest_records_exact_receipt (s : State) (a : Attestation) :
    (attestState s a).attestedProof a.proofId = true := by simp [attestState, put]

theorem attest_other_receipt_unchanged (s : State) (a : Attestation) (key : Hash)
    (h : key ≠ a.proofId) :
    (attestState s a).attestedProof key = s.attestedProof key := by simp [attestState, put, h]

theorem attest_preserves_post_head (s : State) (a : Attestation) :
    (attestState s a).lastPostedBlock = s.lastPostedBlock := rfl

theorem freeze_installs_exact_generation (s : State) (c g : Nat) :
    (freezeState s c g).frozenGeneration c = g := by simp [freezeState, put]

theorem freeze_preserves_post_head (s : State) (c g : Nat) :
    (freezeState s c g).lastPostedBlock = s.lastPostedBlock := rfl

theorem binding_installs_global_floor (s : State) (c m block : Nat) :
    (bindState s c m block).managerOfChannel c = m ∧
    (bindState s c m block).lastPostedBlock c = block := by simp [bindState, put]

theorem post_journals_predecessor (s : State) (c block : Nat) :
    (recordPostState s c block).previousChannelBlock block = s.lastPostedBlock c ∧
    (recordPostState s c block).lastPostedBlock c = block ∧
    (recordPostState s c block).postedChannel block = c := by simp [recordPostState, put]

theorem rollback_restores_exact_predecessor (s : State) (c block : Nat) :
    (rollbackState (recordPostState s c block) block c).lastPostedBlock c = s.lastPostedBlock c ∧
    (rollbackState (recordPostState s c block) block c).postedChannel block = 0 ∧
    (rollbackState (recordPostState s c block) block c).previousChannelBlock block = 0 := by
  simp [rollbackState, recordPostState, put]

theorem current_backing_implies_historical (e : Environment) (s : State) (m c tx funds : Nat)
    (h : hasSignedHeadBacking e s m c tx funds true = true) :
    hasSignedHeadBacking e s m c tx funds false = true := by
  simp only [hasSignedHeadBacking] at *
  split at h <;> simp_all

theorem current_backing_checks_live_head (e : Environment) (s : State) (m c tx funds : Nat)
    (h : hasSignedHeadBacking e s m c tx funds true = true) :
    s.lastPostedBlock c ≤ s.anchorPlusOne (backingStatementKey e m c tx funds) - 1 := by
  simp only [hasSignedHeadBacking] at h
  split at h <;> simp_all

theorem credit_exact_escrow_debit (l : Ledger) (m : Address) (c : Credit)
    (h : c.amount ≤ l.escrow c.token) :
    (creditState l m c).escrow c.token + c.amount = l.escrow c.token := by
  simp [creditState, put]; omega

theorem credit_exact_pending_increment (l : Ledger) (m : Address) (c : Credit) :
    (creditState l m c).pending c.token m = l.pending c.token m + c.amount := by
  simp [creditState, put]

theorem credit_other_token_framed (l : Ledger) (m : Address) (c : Credit) (t : Token)
    (h : t ≠ c.token) :
    (creditState l m c).escrow t = l.escrow t ∧
    (creditState l m c).pending t = l.pending t := by simp [creditState, put, h]

theorem credit_other_manager_framed (l : Ledger) (m other : Address) (c : Credit)
    (h : other ≠ m) :
    (creditState l m c).pending c.token other = l.pending c.token other := by
  simp [creditState, put, h]

theorem latch_exact_digest (s : State) (p : MaterializationPlan) :
    (latchState s p).materializedChannelExit p.channel = p.digest := by simp [latchState, put]

theorem latch_other_channel_framed (s : State) (p : MaterializationPlan) (c : Channel)
    (h : c ≠ p.channel) :
    (latchState s p).materializedChannelExit c = s.materializedChannelExit c := by
  simp [latchState, put, h]

theorem attestation_call_anchor_monotone {e : Environment} {s after : State}
    {manager : Address} {proof : Bytes} {events : List Event}
    (h : attestSignedHeadBacking e s manager proof = .ok (after, events)) (key : Hash) :
    s.anchorPlusOne key ≤ after.anchorPlusOne key := by
  unfold attestSignedHeadBacking at h
  cases hp : prepareAttestation e s manager proof with
  | error error => simp [hp] at h
  | ok a =>
    simp [hp] at h
    rcases h with ⟨rfl, _⟩
    exact attest_anchor_monotone s a key

theorem prepared_attestation_exact_receipt {e : Environment} {s : State}
    {manager : Address} {proof : Bytes} {a : Attestation}
    (h : prepareAttestation e s manager proof = .ok a) :
    a.proofId = backingProofId e manager proof ∧
    a.key = backingStatementKey e manager a.channel a.statement.settledChain a.statement.tokenFundsDigest := by
  unfold prepareAttestation at h
  cases hv : verifyBackingProof e proof with
  | error error => simp [hv] at h
  | ok pi =>
    simp only [hv, result_bind_ok, result_bind_error, result_pure] at h
    cases hs : validateBackingPublicInputs e s manager pi with
    | error error => simp [hs] at h
    | ok statement =>
      simp only [hs, result_bind_ok, result_bind_error, result_pure] at h
      cases hc : (e.manager manager).channelId with
      | error error => simp [hc] at h
      | ok channel =>
        simp only [hc, result_bind_ok, result_bind_error, result_pure, require] at h
        split at h
        · simp at h; cases h; exact ⟨rfl, rfl⟩
        · simp at h

theorem attestation_call_records_exact_bytes {e : Environment} {s after : State}
    {manager : Address} {proof : Bytes} {events : List Event}
    (h : attestSignedHeadBacking e s manager proof = .ok (after, events)) :
    after.attestedProof (backingProofId e manager proof) = true := by
  unfold attestSignedHeadBacking at h
  cases hp : prepareAttestation e s manager proof with
  | error error => simp [hp] at h
  | ok a =>
    have binding := (prepared_attestation_exact_receipt hp).1
    simp [hp] at h
    rcases h with ⟨rfl, _⟩
    rw [← binding]
    exact attest_records_exact_receipt s a

theorem frozen_post_rejected {e : Environment} {s : State} {caller channel block : Nat}
    (rollupCaller : caller = e.rollup) (bound : s.managerOfChannel channel ≠ 0)
    (notExited : s.materializedChannelExit channel = 0) (frozen : s.frozenGeneration channel ≠ 0) :
    recordPost e s caller channel block = .error (.revert "ChannelExitAlreadyFrozen") := by
  simp [recordPost, onlyRollup, require, rollupCaller, bound, notExited, frozen]

theorem materialized_post_rejected {e : Environment} {s : State} {caller channel block : Nat}
    (rollupCaller : caller = e.rollup) (bound : s.managerOfChannel channel ≠ 0)
    (exited : s.materializedChannelExit channel ≠ 0) :
    recordPost e s caller channel block = .error (.revert "ChannelAlreadyExited") := by
  simp [recordPost, onlyRollup, require, rollupCaller, bound, exited]

theorem materialized_cannot_prepare {e : Environment} {s : State} {manager channel anchor : Nat}
    (channelRead : (e.manager manager).channelId = .ok channel)
    (bound : s.managerOfChannel channel = manager) (frozen : s.frozenGeneration channel ≠ 0)
    (exited : s.materializedChannelExit channel ≠ 0) :
    prepareMaterialization e s manager anchor = .error (.revert "ChannelAlreadyExited") := by
  simp [prepareMaterialization, channelRead, require, bound, frozen, exited]

theorem latched_plan_cannot_prepare_again {e : Environment} {s : State} {p : MaterializationPlan}
    (channelRead : (e.manager p.manager).channelId = .ok p.channel)
    (bound : s.managerOfChannel p.channel = p.manager)
    (frozen : s.frozenGeneration p.channel ≠ 0) (nonzero : p.digest ≠ 0) (anchor : Nat) :
    prepareMaterialization e (latchState s p) p.manager anchor =
      .error (.revert "ChannelAlreadyExited") := by
  apply materialized_cannot_prepare (s := latchState s p) channelRead bound frozen
  simpa [latchState, put] using nonzero

theorem read_vector_length {m : ManagerView} {n i : Nat} {seen : List Token} {cs : List Credit}
    (h : readVector m n i seen = .ok cs) : cs.length = n := by
  induction n generalizing i seen cs with
  | zero => simp [readVector] at h; subst cs; rfl
  | succ n ih =>
    simp only [readVector] at h
    cases ht : m.tokenAt i with
    | error error => simp [ht] at h
    | ok token =>
      simp only [ht, result_bind_ok, result_bind_error, result_pure, require] at h
      split at h
      · simp only [result_bind_ok, result_bind_error, result_pure] at h
        cases ha : m.amountAt token with
        | error error => simp [ha] at h
        | ok amount =>
          simp only [ha, result_bind_ok, result_bind_error, result_pure] at h
          cases hr : readVector m n (i + 1) (seen ++ [token]) with
          | error error => simp [hr] at h
          | ok tail =>
            simp [hr] at h; subst cs
            simp [ih hr]
      · simp at h

theorem read_vector_avoids_seen {m : ManagerView} {n i : Nat} {seen : List Token} {cs : List Credit}
    (h : readVector m n i seen = .ok cs) : ∀ c ∈ cs, c.token ∉ seen := by
  induction n generalizing i seen cs with
  | zero => simp [readVector] at h; subst cs; simp
  | succ n ih =>
    simp only [readVector] at h
    cases ht : m.tokenAt i with
    | error error => simp [ht] at h
    | ok token =>
      simp only [ht, result_bind_ok, result_bind_error, result_pure, require] at h
      split at h
      · rename_i fresh
        simp only [result_bind_ok, result_bind_error, result_pure] at h
        cases ha : m.amountAt token with
        | error error => simp [ha] at h
        | ok amount =>
          simp only [ha, result_bind_ok, result_bind_error, result_pure] at h
          cases hr : readVector m n (i + 1) (seen ++ [token]) with
          | error error => simp [hr] at h
          | ok tail =>
            simp [hr] at h; subst cs
            intro c hc
            simp only [List.mem_cons] at hc
            rcases hc with rfl | hc
            · simpa using fresh
            · have hh := ih hr c hc
              simp only [List.mem_append, List.mem_singleton, not_or] at hh
              exact hh.1
      · simp at h

def TokensUnique : List Credit → Prop
  | [] => True
  | c :: cs => (∀ d ∈ cs, c.token ≠ d.token) ∧ TokensUnique cs

theorem read_vector_tokens_unique {m : ManagerView} {n i : Nat} {seen : List Token} {cs : List Credit}
    (h : readVector m n i seen = .ok cs) : TokensUnique cs := by
  induction n generalizing i seen cs with
  | zero => simp [readVector] at h; subst cs; trivial
  | succ n ih =>
    simp only [readVector] at h
    cases ht : m.tokenAt i with
    | error error => simp [ht] at h
    | ok token =>
      simp only [ht, result_bind_ok, result_bind_error, result_pure, require] at h
      split at h
      · simp only [result_bind_ok, result_bind_error, result_pure] at h
        cases ha : m.amountAt token with
        | error error => simp [ha] at h
        | ok amount =>
          simp only [ha, result_bind_ok, result_bind_error, result_pure] at h
          cases hr : readVector m n (i + 1) (seen ++ [token]) with
          | error error => simp [hr] at h
          | ok tail =>
            simp [hr] at h; subst cs
            simp only [TokensUnique]
            refine ⟨?_, ih hr⟩
            intro c hc heq
            have hh := read_vector_avoids_seen hr c hc
            simp [heq] at hh
      · simp at h

theorem read_vector_amounts_from_manager {m : ManagerView} {n i : Nat}
    {seen : List Token} {cs : List Credit} (h : readVector m n i seen = .ok cs) :
    ∀ c ∈ cs, m.amountAt c.token = .ok c.amount := by
  induction n generalizing i seen cs with
  | zero => simp [readVector] at h; subst cs; simp
  | succ n ih =>
    simp only [readVector] at h
    cases ht : m.tokenAt i with
    | error error => simp [ht] at h
    | ok token =>
      simp only [ht, result_bind_ok, result_bind_error, result_pure, require] at h
      split at h
      · simp only [result_bind_ok, result_bind_error, result_pure] at h
        cases ha : m.amountAt token with
        | error error => simp [ha] at h
        | ok amount =>
          simp only [ha, result_bind_ok, result_bind_error, result_pure] at h
          cases hr : readVector m n (i + 1) (seen ++ [token]) with
          | error error => simp [hr] at h
          | ok tail =>
            simp [hr] at h; subst cs
            intro c hc
            simp only [List.mem_cons] at hc
            rcases hc with rfl | hc
            · exact ha
            · exact ih hr c hc
      · simp at h

def transferred : List Credit → Token → Nat
  | [], _ => 0
  | c :: cs, token => (if c.token = token then c.amount else 0) + transferred cs token

theorem successful_credit_accounting {e : Environment} {before after : Ledger}
    {manager : Address} {c : Credit}
    (h : creditChannelExit e before manager c = .ok after) (token : Token) :
    after.escrow token + (if c.token = token then c.amount else 0) = before.escrow token ∧
    after.pending token manager = before.pending token manager + (if c.token = token then c.amount else 0) := by
  simp only [creditChannelExit, require] at h
  split at h <;> simp only [result_bind_ok, result_bind_error, result_pure] at h
  · split at h <;> simp only [result_bind_ok, result_bind_error, result_pure] at h
    · split at h <;> simp only [result_bind_ok, result_bind_error, result_pure] at h
      · rename_i enough
        split at h <;> simp at h
        subst after
        by_cases ht : token = c.token
        · subst token
          exact ⟨by simpa using credit_exact_escrow_debit before manager c (of_decide_eq_true enough),
            by simpa using credit_exact_pending_increment before manager c⟩
        · simp [creditState, put, ht, Ne.symm ht]

theorem successful_vector_accounting {e : Environment} {before after : Ledger}
    {manager : Address} {cs : List Credit}
    (h : creditVector e manager before cs = .ok after) (token : Token) :
    after.escrow token + transferred cs token = before.escrow token ∧
    after.pending token manager = before.pending token manager + transferred cs token := by
  induction cs generalizing before with
  | nil => simp [creditVector] at h; subst after; simp [transferred]
  | cons c cs ih =>
    simp only [creditVector] at h
    by_cases zero : c.amount = 0
    · simp [zero] at h
      simpa [transferred, zero] using ih h
    · simp only [beq_iff_eq, zero, ↓reduceIte] at h
      cases hc : creditChannelExit e before manager c with
      | error error => simp [hc] at h
      | ok middle =>
        simp only [hc, result_bind_ok, result_bind_error, result_pure] at h
        have first := successful_credit_accounting hc token
        have rest := ih h
        simp only [transferred] at *
        constructor <;> omega

theorem materialization_call_exact_accounting {e : Environment} {before after : World}
    {manager : Address} {proof : Bytes} {events : List Event}
    (h : materializeSignedHead e before manager proof = .ok (after, events)) :
    ∃ p, prepareSignedHead e before.storage manager proof = .ok p ∧
      after.storage = latchState before.storage p ∧
      (∀ token, after.ledger.escrow token + transferred p.credits token = before.ledger.escrow token ∧
        after.ledger.pending token manager = before.ledger.pending token manager + transferred p.credits token) := by
  unfold materializeSignedHead at h
  cases hp : prepareSignedHead e before.storage manager proof with
  | error error => simp [hp] at h
  | ok p =>
    simp only [hp, result_bind_ok] at h
    cases hc : creditVector e manager before.ledger p.credits with
    | error error => simp [hc] at h
    | ok ledger =>
      simp [hc] at h
      rcases h with ⟨rfl, _⟩
      exact ⟨p, rfl, rfl, fun token => successful_vector_accounting hc token⟩

theorem failed_materialization_rolls_back_all {e : Environment} {before : World}
    {manager : Address} {proof : Bytes} {error : Error}
    (h : materializeSignedHead e before manager proof = .error error) :
    commit before (materializeSignedHead e before manager proof) = (before, []) := by
  rw [h]; rfl

theorem signed_head_reverification_failure {e : Environment} {s : State}
    {manager : Address} {proof : Bytes} {error : Error}
    (h : e.verifyCompact proof = .error error) :
    prepareSignedHead e s manager proof = .error (.revert "BackingProofInvalid") := by
  simp [prepareSignedHead, verifier_failure_rejected h]

theorem validated_pi_has_exact_length {e : Environment} {s : State}
    {manager : Address} {pi : List Nat} {statement : BackingStatement}
    (h : validateBackingPublicInputs e s manager pi = .ok statement) : pi.length = 26 := by
  unfold validateBackingPublicInputs at h
  by_cases count : pi.length = 26
  · exact count
  · simp [require, count] at h

theorem freeze_call_installs_only_matching_generation {e : Environment} {s after : State}
    {caller channel generation : Nat} {events : List Event}
    (h : freezeFromManager e s caller channel generation = .ok (after, events)) :
    s.managerOfChannel channel = caller ∧ generation ≠ 0 ∧
      after.frozenGeneration channel = generation := by
  unfold freezeFromManager at h
  simp only [require] at h
  split at h <;> simp only [result_bind_ok, result_bind_error] at h
  · rename_i bound
    split at h <;> simp only [result_bind_ok, result_bind_error] at h
    · split at h <;> simp only [result_bind_ok, result_bind_error] at h
      · cases hc : (e.manager caller).channelId with
        | error error => simp [hc] at h
        | ok actualChannel =>
          simp only [hc, result_bind_ok] at h
          split at h <;> simp only [result_bind_ok, result_bind_error] at h
          · cases hg : (e.manager caller).generation with
            | error error => simp [hg] at h
            | ok actualGeneration =>
              simp only [hg, result_bind_ok] at h
              split at h <;> simp only [result_bind_ok, result_bind_error] at h
              · rename_i generationMatches
                cases hs : (e.manager caller).status with
                | error error => simp [hs] at h
                | ok status =>
                  simp only [hs, result_bind_ok] at h
                  split at h <;> simp at h
                  rcases h with ⟨rfl, _⟩
                  have gm : actualGeneration = generation ∧ generation ≠ 0 := by simpa using generationMatches
                  exact ⟨by simpa using bound, gm.2,
                    freeze_installs_exact_generation s channel generation⟩

theorem unfreeze_call_clears_matching_generation {s after : State}
    {caller channel generation : Nat} {events : List Event}
    (h : unfreezeFromManager s caller channel generation = .ok (after, events)) :
    s.frozenGeneration channel = generation ∧ generation ≠ 0 ∧ after.frozenGeneration channel = 0 := by
  unfold unfreezeFromManager at h
  simp only [require] at h
  split at h <;> simp only [result_bind_ok, result_bind_error] at h
  · split at h <;> simp only [result_bind_ok, result_bind_error] at h
    · rename_i nonzero
      split at h <;> simp only [result_bind_ok, result_bind_error] at h
      · rename_i matching
        split at h <;> simp at h
        rcases h with ⟨rfl, _⟩
        have eqg : s.frozenGeneration channel = generation := by simpa using matching
        exact ⟨eqg, by simpa [eqg] using nonzero, freeze_installs_exact_generation s channel 0⟩

/-- Extracts the runtime's local guards, not an assumed whole-state safety fact. -/
theorem prepared_materialization_guards {e : Environment} {s : State} {manager anchor : Nat}
    {p : MaterializationPlan} (h : prepareMaterialization e s manager anchor = .ok p) :
    p.manager = manager ∧ (e.manager manager).channelId = .ok p.channel ∧
    s.managerOfChannel p.channel = manager ∧ s.frozenGeneration p.channel ≠ 0 ∧
    s.materializedChannelExit p.channel = 0 ∧ p.digest ≠ 0 ∧
    s.lastPostedBlock p.channel ≤ anchor ∧
    p.credits.length = p.tokenCount ∧ TokensUnique p.credits ∧
    (∀ c ∈ p.credits, (e.manager manager).amountAt c.token = .ok c.amount) := by
  unfold prepareMaterialization at h
  cases hc : (e.manager manager).channelId with
  | error error => simp [hc] at h
  | ok channel =>
    simp only [hc, result_bind_ok, require] at h
    split at h <;> simp only [result_bind_ok, result_bind_error] at h
    rename_i bound
    split at h <;> simp only [result_bind_ok, result_bind_error] at h
    rename_i frozen
    split at h <;> simp only [result_bind_ok, result_bind_error] at h
    rename_i notExited
    cases hs : (e.manager manager).status with
    | error error => simp [hs] at h
    | ok status =>
      simp only [hs, result_bind_ok] at h
      split at h <;> simp only [result_bind_ok, result_bind_error] at h
      cases hg : (e.manager manager).generation with
      | error error => simp [hg] at h
      | ok generation =>
        simp only [hg, result_bind_ok] at h
        split at h <;> simp only [result_bind_ok, result_bind_error] at h
        cases hd : (e.manager manager).closeDigest with
        | error error => simp [hd] at h
        | ok digest =>
          simp only [hd, result_bind_ok] at h
          cases hr : (e.manager manager).stateRoot with
          | error error => simp [hr] at h
          | ok root =>
            simp only [hr, result_bind_ok] at h
            split at h <;> simp only [result_bind_ok, result_bind_error] at h
            rename_i nonzero
            cases hf : e.isFinalizedRoot root with
            | error error => simp [hf] at h
            | ok finalized =>
              simp only [hf, result_bind_ok] at h
              split at h <;> simp only [result_bind_ok, result_bind_error] at h
              cases hl : e.latestFinalized with
              | error error => simp [hl] at h
              | ok last =>
                simp only [hl, result_bind_ok] at h
                split at h <;> simp only [result_bind_ok, result_bind_error] at h
                rename_i currentAnchor
                cases hn : (e.manager manager).tokenCount with
                | error error => simp [hn] at h
                | ok count =>
                  simp only [hn, result_bind_ok] at h
                  split at h <;> simp only [result_bind_ok, result_bind_error] at h
                  cases hv : readVector (e.manager manager) count 0 [] with
                  | error error => simp [hv] at h
                  | ok vector =>
                    simp [hv] at h; subst p
                    have cur : anchor ≤ last ∧ s.lastPostedBlock channel ≤ anchor := by simpa using currentAnchor
                    exact ⟨rfl, rfl, by simpa using bound, by simpa using frozen,
                      by simpa using notExited, by simpa using nonzero, cur.2,
                      read_vector_length hv, read_vector_tokens_unique hv, read_vector_amounts_from_manager hv⟩

theorem successful_plan_refuses_second_materialization {e : Environment} {s : State}
    {manager anchor : Nat} {p : MaterializationPlan}
    (h : prepareMaterialization e s manager anchor = .ok p) (nextAnchor : Nat) :
    prepareMaterialization e (latchState s p) manager nextAnchor =
      .error (.revert "ChannelAlreadyExited") := by
  rcases prepared_materialization_guards h with ⟨hm, hc, hb, hf, _, hn, _⟩
  have result := latched_plan_cannot_prepare_again (e := e) (s := s) (p := p)
    (by simpa [hm] using hc) (by simpa [hm] using hb) hf hn nextAnchor
  simpa [hm] using result

theorem prepared_signed_head_requires_receipt_and_local_checks {e : Environment} {s : State}
    {manager : Address} {proof : Bytes} {p : MaterializationPlan}
    (h : prepareSignedHead e s manager proof = .ok p) :
    s.attestedProof (backingProofId e manager proof) = true ∧
    ∃ anchor, prepareMaterialization e s manager anchor = .ok p := by
  unfold prepareSignedHead at h
  cases hv : verifyBackingProof e proof with
  | error error => simp [hv] at h
  | ok pi =>
    simp only [hv, result_bind_ok] at h
    cases hs : validateBackingPublicInputs e s manager pi with
    | error error => simp [hs] at h
    | ok statement =>
      simp only [hs, result_bind_ok, require] at h
      split at h <;> simp only [result_bind_ok, result_bind_error] at h
      rename_i receipt
      cases ht : (e.manager manager).settledChain with
      | error error => simp [ht] at h
      | ok settled =>
        simp only [ht, result_bind_ok] at h
        split at h <;> simp only [result_bind_ok, result_bind_error] at h
        cases hf : (e.manager manager).tokenFundsDigest with
        | error error => simp [hf] at h
        | ok funds =>
          simp only [hf, result_bind_ok] at h
          split at h <;> simp only [result_bind_ok, result_bind_error] at h
          exact ⟨receipt, statement.anchor, h⟩

/-- Complete vector and per-token conservation are consequences of this call's
actual checks. No equation relating these funds to legitimate L2 ownership is
asserted; that separate claim requires the compact-proof refinement boundary. -/
theorem materialization_call_complete_vector {e : Environment} {before after : World}
    {manager : Address} {proof : Bytes} {events : List Event}
    (h : materializeSignedHead e before manager proof = .ok (after, events)) :
    ∃ p : MaterializationPlan, p.manager = manager ∧ p.credits.length = p.tokenCount ∧ TokensUnique p.credits ∧
      (∀ c ∈ p.credits, (e.manager manager).amountAt c.token = .ok c.amount) ∧
      after.storage.materializedChannelExit p.channel = p.digest ∧ p.digest ≠ 0 ∧
      (∀ token, after.ledger.escrow token + transferred p.credits token = before.ledger.escrow token ∧
        after.ledger.pending token manager = before.ledger.pending token manager + transferred p.credits token) := by
  rcases materialization_call_exact_accounting h with ⟨p, hp, hs, accounting⟩
  rcases (prepared_signed_head_requires_receipt_and_local_checks hp).2 with ⟨anchor, localChecks⟩
  rcases prepared_materialization_guards localChecks with ⟨hm, _, _, _, _, hd, _, hl, hu, ha⟩
  exact ⟨p, hm, hl, hu, ha, by rw [hs]; exact latch_exact_digest before.storage p, hd, accounting⟩

/-- The same Manager cannot materialize a second vector after this successful
call, even using different proof bytes. This statement fixes coherent getter
observations; arbitrary intervening EVM calls require the separate refinement. -/
theorem materialization_call_one_shot {e : Environment} {before after : World}
    {manager : Address} {proof : Bytes} {events : List Event}
    (h : materializeSignedHead e before manager proof = .ok (after, events))
    (nextProof : Bytes) (nextWorld : World) (nextEvents : List Event) :
    materializeSignedHead e after manager nextProof ≠ .ok (nextWorld, nextEvents) := by
  intro next
  rcases materialization_call_exact_accounting h with ⟨p, hp, hs, _⟩
  rcases (prepared_signed_head_requires_receipt_and_local_checks hp).2 with ⟨anchor, localChecks⟩
  rcases materialization_call_exact_accounting next with ⟨q, hq, _⟩
  rcases (prepared_signed_head_requires_receipt_and_local_checks hq).2 with ⟨nextAnchor, nextChecks⟩
  rw [hs, successful_plan_refuses_second_materialization localChecks nextAnchor] at nextChecks
  contradiction

theorem zero_vector_skips_all_external_credits (e : Environment) (l : Ledger) (manager : Address) :
    creditVector e manager l [⟨0, 0⟩, ⟨3, 0⟩] = .ok l := rfl

theorem normal_post_then_rollback_restores_head :
    (rollbackState (recordPostState (bindState empty 7 9 12) 7 15) 15 7).lastPostedBlock 7 = 12 := by
  decide

end Zkp.Implementation.CloseFunding
