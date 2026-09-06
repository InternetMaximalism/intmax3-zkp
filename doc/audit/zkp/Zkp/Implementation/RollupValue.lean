import Std

/-!
# IntmaxRollup source-oriented value and lifecycle paths

Manual source-oriented translation of the monetary, registration, authority,
posting/submission, finality/fraud, stake and rollback functions in IntmaxRollup.sol
(2353 lines, runtime 05ec7ae). The full-source map separates modeled control flow
from genuine ABI, assembly, callback, crypto and resource boundaries. This is NOT
an extracted Solidity/EVM, all-entrypoint temporal closure, or full Rollup proof.

Native escrow and ERC20 index zero are distinct storage locations. Escrow is
POOLED, not channel-scoped. The proved isolation is token/recipient ledger
framing, not ownership of pooled collateral or proof soundness. In particular,
the source comment saying the global ceiling alone prevents cross-channel theft
is not promoted to a theorem. Entitlement depends on the actual pinned withdrawal
proof and the bound materializer/Manager protocol, modeled as dependencies.

Nat values denote canonical unsigned ABI/getter values; represented monetary
and counter arithmetic checks source widths, including the uint64 deposit
counter and explicit uint64 PI cast. Returned root limbs are MASKED; only the
pis-hash comparison is strict. No nonexistent u63 check is inserted at pi[16].

External token/native calls receive the exact pre-call state and typed request,
and may return callback-mutated storage. They are NOT assumed harmless. The lock
is visible at those calls and rejects guarded reentry; unguarded calls are NOT
universally excluded. Local and withdrawal-loop accounting theorems cover actual updates. Any
composition through callbacks requires explicit storage-frame/EVM assumptions.
`commit` models outer rollback of tracked storage/logs, not an EVM proof.
Returned events are only the Rollup's own final-success log projection, not a
global ordered execution trace: in particular withdrawToken emits its event
before the balance/token callbacks in Solidity. Callee logs, callback-relative
event ordering, gas, memory allocation and exceptional resource exhaustion are
not represented. Combining the two consume-guard writes preserves their final
effect because no external call intervenes in that source helper.
Static balance reads preserve storage; SafeERC20 acceptance, ABI/keccak encoding,
actual custody and token honesty remain separate dependencies.
-/

namespace Zkp.Implementation.RollupValue

abbrev Address := Nat
abbrev Token := Nat
abbrev Hash := Nat
abbrev Bytes := List UInt8

/-- Fixed-width big-endian bytes; ABI canonicality is a separate obligation. -/
def wordBytes (width value : Nat) : Bytes :=
  (List.range width).map fun i => UInt8.ofNat (value / 256 ^ (width - 1 - i) % 256)

def u32Limit : Nat := 2 ^ 32
def u64Limit : Nat := 2 ^ 64
def u256Limit : Nat := 2 ^ 256
def ipw2Domain : Nat := 0x49505732

inductive Asset where
  | native
  | erc20 (token : Token)
  deriving DecidableEq, Repr

def assetOfToken (t : Token) : Asset := if t = 0 then .native else .erc20 t

inductive Error where
  | revert (name : String)
  | revertArgs (name : String) (arguments : List Nat)
  | panic (name : String)
  | external (data : Bytes)
  deriving DecidableEq, Repr

abbrev Result := Except Error

@[simp] theorem result_bind_ok {α β : Type} (x : α) (f : α → Result β) :
    ((Except.ok x : Result α) >>= f) = f x := rfl
@[simp] theorem result_bind_error {α β : Type} (e : Error) (f : α → Result β) :
    ((Except.error e : Result α) >>= f) = .error e := rfl
@[simp] theorem result_pure {α : Type} (x : α) : (pure x : Result α) = .ok x := rfl

def require (condition : Bool) (error : Error) : Result Unit :=
  if condition then .ok () else .error error

def put {κ α : Type} [DecidableEq κ] (f : κ → α) (key : κ) (value : α) : κ → α :=
  fun k => if k = key then value else f k

structure Withdrawal where
  recipient : Address
  token : Token
  amount : Nat
  nullifier : Hash
  auxData : Hash
  deriving DecidableEq, Repr

structure DepositRecord where
  depositor : Address
  recipient : Hash
  token : Token
  amount : Nat
  auxData : Hash
  deriving DecidableEq, Repr

structure Checkpoint where
  depositChain : Hash
  registrationChain : Hash
  packedCounts : Nat
  deriving DecidableEq, Repr

structure Submission where
  commitment : Hash := 0
  submitter : Address := 0
  finalized : Bool := false
  submittedAt : Nat := 0
  stateRoot : Hash := 0
  deriving DecidableEq, Repr

structure StakeInfo where
  submitter : Address := 0
  spent : Bool := false
  deriving DecidableEq, Repr

structure SubBlock where
  channelId : Nat
  timestamp : Nat
  txTreeRoot : Hash
  keyIds : List Nat
  deriving DecidableEq, Repr

structure BatchMetadata where
  startBlock : Nat := 0
  endBlock : Nat := 0
  previousHash : Hash := 0
  previousDepositChain : Hash := 0
  roundBefore : Nat := 0
  roundAfter : Nat := 0
  processedBefore : Nat := 0
  previousRegistrationChain : Hash := 0
  deriving DecidableEq, Repr

structure ValidityPIs where
  initialBlock : Nat
  initialChain : Hash
  initialRoot : Hash
  finalBlock : Nat
  finalChain : Hash
  finalRoot : Hash
  prover : Address
  deriving DecidableEq, Repr

structure Registration where
  channel : Nat
  bpSlot : Nat
  delegates : Nat
  pkGs : List Hash
  pkBs : List Hash
  regev : List Hash
  recipients : List Address
  deriving DecidableEq, Repr

structure MemberSlot where
  pkG : Hash
  pkB : Hash
  regev : Hash
  recipient : Address
  deriving DecidableEq, Repr

/-- All non-monetary mutable fields, kept separate only for ledger framing. -/
structure ChainState where
  producers : Address → Bool := fun _ => false
  producerAdmin : Address := 0
  kzg : Address := 0
  blockHash : Hash := 0
  blockNumber : Nat := 0
  round : Nat := 0
  depositChain : Hash := 0
  registrationChain : Hash := 0
  processedDeposits : Nat := 0
  blockDeposit : Nat → Hash := fun _ => 0
  blockRegistration : Nat → Hash := fun _ => 0
  blockHashAt : Nat → Hash := fun _ => 0
  memberCommitment : Nat → Hash := fun _ => 0
  bpSlot : Nat → Nat := fun _ => 0
  bpPkG : Nat → Hash := fun _ => 0
  submissions : Nat → Submission := fun _ => {}
  stakes : Nat → StakeInfo := fun _ => {}
  batches : Nat → BatchMetadata := fun _ => {}
  nextSubmission : Nat := 0
  finalizedRoot : Hash := 0
  finalizedBlock : Nat := 0

structure State where
  escrow : Asset → Nat
  pending : Asset → Address → Nat
  tokenAddress : Token → Address
  used : Hash → Bool
  authorized : Hash → Bool
  registeredManager : Address → Bool
  materializer : Address
  status : Nat
  depositCount : Nat
  pendingDepositChain : Hash
  pendingRegistrationChain : Hash
  registrationCount : Nat
  deposits : Nat → Option DepositRecord
  checkpoints : Hash → Checkpoint
  finalizedRoot : Hash → Bool
  chain : ChainState := {}

def empty : State :=
  ⟨fun _ => 0, fun _ _ => 0, fun _ => 0, fun _ => false, fun _ => false,
   fun _ => false, 0, 1, 0, 0, 0, 0, fun _ => none,
   fun _ => ⟨0, 0, 0⟩, fun _ => false, {}⟩

inductive Event where
  | tokenRegistered (token address : Nat)
  | authorized (digest manager : Nat)
  | deposited (index : Nat) (record : DepositRecord) (newHash : Hash)
  | nativeWithdrawn (recipient amount nullifier blockNumber : Nat)
  | erc20Withdrawn (recipient token amount nullifier blockNumber : Nat)
  | tokenWithdrawalClaimed (recipient token amount : Nat)
  | managerRegistered (manager : Address)
  | blockProducerSet (producer : Address) (allowed : Bool)
  | blockProducerAdminSet (admin : Address)
  | channelRegistered (index channel bpSlot : Nat) (pkGs regev recipients : List Nat) (memberRoot regevRoot chain : Hash)
  | blockPosted (height channel : Nat) (keys : List Nat) (tree chain : Hash)
  | submitted (id submitter commitment proofHash proofLength stateRoot : Nat)
  | finalized (id stateRoot : Nat)
  | finalizeRejected (id reason : Nat)
  | fraudConfirmed (id reporter : Nat)
  | withdrawalCredited (recipient amount : Nat)
  deriving DecidableEq, Repr

inductive HashInput where
  | deposit (previous : Hash) (record : DepositRecord)
  | pendingPin (depositChain registrationChain : Hash)
  | withdrawalAuth (domain : Nat) (recipient token amount auxData : Nat)
  | withdrawalLeaf (previous : Hash) (leaf : Withdrawal)
  | withdrawalPis (chain prover root blockNumber : Nat)
  | validityPis (pis : ValidityPIs)
  | block (previous : Hash) (b : SubBlock) (depositChain registrationChain : Hash)
  | closeMembers (domain count : Nat) (padded : List Hash)
  | channelRegistration (previous : Hash) (channel bp count delegates : Nat) (slots : List MemberSlot)
  | registrationBytes (header : Bytes) (slots : List MemberSlot)
  | identityArray (identities : List Hash)
  | rawBytes (bytes : Bytes)
  deriving DecidableEq, Repr

/-- These records specify exact ABI roles/order; byte serialization is a boundary. -/
inductive TokenCall where
  | transferFrom (token sender to amount : Nat)
  | transfer (token to amount : Nat)
  deriving DecidableEq, Repr

structure BalanceReply where
  ok : Bool
  size : Nat
  firstWord : Nat

inductive Getter where
  | allowedChainId
  | core
  | closeFundingMaterializer
  deriving DecidableEq, Repr

/-- Runtime observations and typed external boundaries for the remaining paths.
Every stateful call sees the exact pre-call storage and may return callbacks.
STATICCALL getters/attestation/verifiers cannot directly mutate this state. -/
structure LifecycleEnvironment where
  validityAdapter : Address
  fraudTreasury : Address
  getter : Address → Getter → Result Nat
  materializerGetter : State → Address → BalanceReply
  bindManager : State → Address → Address → Result State
  recordPost : State → Address → Nat → Nat → Result State
  rollbackPost : State → Address → Nat → Result State
  postCommitment : State → Address → Hash → Nat → Nat → Result (State × Hash)
  isAttested : State → Address → Nat → Hash → Hash → Nat → Result Bool
  attest : State → Address → Address → Nat → Bytes → Bytes → Result (State × Hash)
  classify : Address → Bytes → Hash → Nat → Result Nat
  encodeError : Error → Bytes
  gasAtEntry : Nat
  gasAtReserve : Nat
  gasAtBudget : Nat
  gasAfterFailure : Nat

structure Environment where
  caller : Address
  self : Address
  value : Nat
  chainId : Nat
  deploymentChainId : Nat
  deployer : Address
  withdrawalAdapter : Address
  blockNumber : Nat
  codeLength : Address → Nat
  hash : HashInput → Hash
  balanceOf : State → Address → Address → BalanceReply
  tokenCall : State → TokenCall → Result State
  sendNative : State → Address → Nat → Result State
  verifyCompact : Address → Bytes → Result (List Nat)
  lifecycle : LifecycleEnvironment

def releaseRuntime (e : Environment) : Result Unit :=
  require (e.chainId == e.deploymentChainId) (.revert "ReleaseRuntimeUnavailable")

def nonReentrantBefore (s : State) : Result State :=
  if s.status = 2 then .error (.revert "ReentrantCall") else .ok { s with status := 2 }

def nonReentrantAfter (s : State) : State := { s with status := 1 }

def guarded (s : State) (body : State → Result (State × List Event)) : Result (State × List Event) := do
  let locked ← nonReentrantBefore s
  let (after, events) ← body locked
  pure (nonReentrantAfter after, events)

def commit (before : State) (result : Result (State × List Event)) : State × List Event :=
  match result with
  | .error _ => (before, [])
  | .ok pair => pair

def requireDeployer (e : Environment) : Result Unit :=
  require (e.caller == e.deployer) (.revert "OnlyDeployer")

def registerToken (e : Environment) (s : State) (index token : Nat) : Result (State × List Event) := do
  requireDeployer e
  require (index != 0) (.revert "TokenIndexZeroReservedForEth")
  require (token != 0) (.revert "TokenAddressZeroReserved")
  require (s.tokenAddress index == 0) (.revert "TokenIndexAlreadyRegistered")
  require (e.codeLength token != 0) (.revert "TokenNotAContract")
  pure ({ s with tokenAddress := put s.tokenAddress index token }, [.tokenRegistered index token])

def authorizePartialWithdrawal (e : Environment) (s : State) (digest : Hash) :
    Result (State × List Event) := do
  require (s.registeredManager e.caller) (.revert "NotRegisteredSettlementManager")
  pure ({ s with authorized := put s.authorized digest true }, [.authorized digest e.caller])

def withdrawalAuthDigest (e : Environment) (w : Withdrawal) : Hash :=
  e.hash (.withdrawalAuth ipw2Domain w.recipient w.token w.amount w.auxData)

def consumedState (s : State) (digest : Hash) (w : Withdrawal) : State :=
  { s with used := put s.used w.nullifier true
           authorized := if w.auxData = 0 then s.authorized else put s.authorized digest false }

def consumeWithdrawalGuard (e : Environment) (s : State) (w : Withdrawal) : Result State := do
  require (!s.used w.nullifier) (.revert "WithdrawalNullifierUsed")
  if w.auxData != 0 then
    require (s.authorized (withdrawalAuthDigest e w)) (.revert "PartialWithdrawalNotAuthorized")
  pure (consumedState s (withdrawalAuthDigest e w) w)

def creditState (s : State) (asset : Asset) (recipient amount : Nat) : State :=
  { s with escrow := put s.escrow asset (s.escrow asset - amount)
           pending := put s.pending asset (put (s.pending asset) recipient (s.pending asset recipient + amount)) }

def creditEscrow (s : State) (asset : Asset) (recipient amount : Nat) : Result State := do
  require (amount ≤ s.escrow asset) (.panic "uint256 underflow")
  require (s.pending asset recipient + amount < u256Limit) (.panic "uint256 overflow")
  pure (creditState s asset recipient amount)

def creditNativeEscrow (s : State) (recipient amount : Nat) : Result State :=
  creditEscrow s .native recipient amount

def creditTokenEscrow (s : State) (index recipient amount : Nat) : Result State :=
  creditEscrow s (.erc20 index) recipient amount

def creditChannelExit (e : Environment) (s : State) (manager index amount : Nat) : Result State := do
  releaseRuntime e
  require (e.caller == s.materializer) (.revert "InvalidChannelExitManager")
  if index = 0 then creditNativeEscrow s manager amount else creditTokenEscrow s index manager amount

def tokenBalanceOf (e : Environment) (s : State) (token account : Address) : Result Nat :=
  let reply := e.balanceOf s token account
  if !reply.ok || reply.size < 32 then .error (.external []) else .ok reply.firstWord

def pendingChainsPin (e : Environment) (s : State) : Hash :=
  e.hash (.pendingPin s.pendingDepositChain s.pendingRegistrationChain)

def recordCheckpoint (e : Environment) (s : State) : State :=
  let packed := 1 ||| Nat.shiftLeft s.depositCount 1 ||| Nat.shiftLeft s.registrationCount 65
  { s with checkpoints := put s.checkpoints (pendingChainsPin e s) (⟨s.pendingDepositChain, s.pendingRegistrationChain, packed⟩) }

def depositEscrowState (s : State) (asset : Asset) (amount : Nat) : State :=
  { s with escrow := put s.escrow asset (s.escrow asset + amount) }

def finishDeposit (e : Environment) (s : State) (d : DepositRecord) : Result (State × List Event) := do
  require (s.depositCount + 1 < u64Limit) (.panic "uint64 overflow")
  let index := s.depositCount
  let chain := e.hash (.deposit s.pendingDepositChain d)
  let next := { s with depositCount := index + 1, pendingDepositChain := chain, deposits := put s.deposits index (some d) }
  pure (recordCheckpoint e next, [.deposited index d chain])

def depositBody (e : Environment) (s : State) (recipient index amount aux : Nat) :
    Result (State × List Event) := do
  let after ← if index = 0 then do
      require (e.value == amount) (.revert "EthDepositValueMismatch")
      require (s.escrow .native + amount < u256Limit) (.panic "uint256 overflow")
      pure (depositEscrowState s .native amount)
    else do
      require (e.value == 0) (.revert "NonEthDepositMustNotCarryEth")
      let token := s.tokenAddress index
      require (token != 0) (.revert "TokenIndexNotRegistered")
      let before ← tokenBalanceOf e s token e.self
      let callback ← e.tokenCall s (.transferFrom token e.caller e.self amount)
      let balance ← tokenBalanceOf e callback token e.self
      require (before ≤ balance) (.panic "uint256 underflow")
      require (balance - before == amount) (.revert "TokenDepositAmountMismatch")
      require (callback.escrow (.erc20 index) + amount < u256Limit) (.panic "uint256 overflow")
      pure (depositEscrowState callback (.erc20 index) amount)
  finishDeposit e after ⟨e.caller, recipient, index, amount, aux⟩

def deposit (e : Environment) (s : State) (recipient index amount aux : Nat) :
    Result (State × List Event) := do
  releaseRuntime e
  guarded s (fun locked => depositBody e locked recipient index amount aux)

def pullState (s : State) (asset : Asset) (caller amount : Nat) : State :=
  { s with pending := put s.pending asset (put (s.pending asset) caller (s.pending asset caller - amount)) }

def withdrawBody (e : Environment) (s : State) (amount : Nat) : Result (State × List Event) := do
  require (amount != 0 && amount ≤ s.pending .native e.caller) (.revert "NothingToWithdraw")
  let debited := pullState s .native e.caller amount
  let callback ← (e.sendNative debited e.caller amount).mapError (fun _ => .revert "WithdrawTransferFailed")
  pure (callback, [])

def withdraw (e : Environment) (s : State) (amount : Nat) : Result (State × List Event) := do
  releaseRuntime e
  guarded s (fun locked => withdrawBody e locked amount)

def withdrawTokenBody (e : Environment) (s : State) (index amount : Nat) :
    Result (State × List Event) := do
  let token := s.tokenAddress index
  require (token != 0) (.revert "TokenIndexNotRegistered")
  require (amount != 0 && amount ≤ s.pending (.erc20 index) e.caller) (.revert "NothingToWithdrawForToken")
  let debited := pullState s (.erc20 index) e.caller amount
  let before ← tokenBalanceOf e debited token e.caller
  let callback ← e.tokenCall debited (.transfer token e.caller amount)
  let balance ← tokenBalanceOf e callback token e.caller
  require (before ≤ balance) (.panic "uint256 underflow")
  require (balance - before == amount) (.revert "TokenWithdrawalAmountMismatch")
  pure (callback, [.tokenWithdrawalClaimed e.caller index amount])

def withdrawToken (e : Environment) (s : State) (index amount : Nat) :
    Result (State × List Event) := do
  releaseRuntime e
  guarded s (fun locked => withdrawTokenBody e locked index amount)

def limbsToBytes32 (pi : List Nat) (offset : Nat) : Hash :=
  ((pi.drop offset).take 8).foldl (fun acc limb => acc * u32Limit + limb % u32Limit) 0

def limbsMatchBytes32 (pi : List Nat) (offset value : Nat) : Bool :=
  ([0,1,2,3,4,5,6,7] : List Nat).all fun i =>
    pi[offset + i]? == some ((value / 2 ^ (224 - i * 32)) % u32Limit)

def foldWithdrawalLeaf (e : Environment) (previous : Hash) (w : Withdrawal) : Hash :=
  e.hash (.withdrawalLeaf previous w)

def withdrawalPisHash (e : Environment) (chain prover root block : Nat) : Hash :=
  e.hash (.withdrawalPis chain prover root block) % (2 ^ 253)

def verifyWithdrawalSet (e : Environment) (s : State) (ws : List Withdrawal)
    (prover : Address) (proof : Bytes) : Result Nat := do
  require (!ws.isEmpty) (.revert "WithdrawalEmptySet")
  let pi ← (e.verifyCompact e.withdrawalAdapter proof).mapError (fun _ => .revert "WithdrawalProofInvalid")
  require (pi.length == 17) (.revert "WithdrawalPublicInputsMismatch")
  let root := limbsToBytes32 pi 8
  require (s.finalizedRoot root) (.revert "WithdrawalExtCommitmentMismatch")
  let block := (pi.getD 16 0) % u64Limit
  let chain := ws.foldl (foldWithdrawalLeaf e) 0
  let pisHash := withdrawalPisHash e chain prover root block
  require (limbsMatchBytes32 pi 0 pisHash) (.revert "WithdrawalPublicInputsMismatch")
  pure block

def withdrawalAsset (native : Bool) (w : Withdrawal) : Asset := if native then .native else .erc20 w.token

def withdrawOne (e : Environment) (native : Bool) (s : State) (w : Withdrawal) : Result State := do
  if native then require (w.token == 0) (.revert "WithdrawalNotEthToken")
  else
    require (w.token != 0) (.revert "WithdrawalNotErc20Token")
    require (s.tokenAddress w.token != 0) (.revert "TokenIndexNotRegistered")
  let consumed ← consumeWithdrawalGuard e s w
  creditEscrow consumed (withdrawalAsset native w) w.recipient w.amount

def withdrawLeaves (e : Environment) (native : Bool) (block : Nat) :
    State → List Withdrawal → Result (State × List Event)
  | s, [] => pure (s, [])
  | s, w :: ws => do
    let credited ← withdrawOne e native s w
    let event := if native then Event.nativeWithdrawn w.recipient w.amount w.nullifier block
      else Event.erc20Withdrawn w.recipient w.token w.amount w.nullifier block
    let (after, events) ← withdrawLeaves e native block credited ws
    pure (after, event :: events)

/-- Deliberately no releaseRuntime modifier: the two source proof-backed
endpoints only have nonReentrant. The direct pull and close credit do pin chain. -/
def withdrawNative (e : Environment) (s : State) (ws : List Withdrawal)
    (prover : Address) (proof : Bytes) : Result (State × List Event) :=
  guarded s fun locked => do
    let block ← verifyWithdrawalSet e locked ws prover proof
    withdrawLeaves e true block locked ws

def withdrawERC20 (e : Environment) (s : State) (ws : List Withdrawal)
    (prover : Address) (proof : Bytes) : Result (State × List Event) :=
  guarded s fun locked => do
    let block ← verifyWithdrawalSet e locked ws prover proof
    withdrawLeaves e false block locked ws

/-! ## Constructor, authority, registration and all remaining lifecycle bodies -/

def stakeAmount : Nat := 10 ^ 18
def fraudReward : Nat := stakeAmount * 90 / 100
def treasuryShare : Nat := stakeAmount - fraudReward
def finalizeDeadline : Nat := 3600
def minVerifyGas : Nat := 25000000
def goldilocks : Nat := 0xffffffff00000001

def checkedAdd (a b limit : Nat) : Result Nat := do
  require (a + b < limit) (.panic "unsigned overflow")
  pure (a + b)

def requirePinnedVerifier (e : Environment) (adapter : Address) : Result Address := do
  let invalid := Error.revertArgs "InvalidPinnedMleVerifier" [adapter]
  require (e.codeLength adapter != 0) invalid
  let chain ← (e.lifecycle.getter adapter .allowedChainId).mapError (fun _ => invalid)
  require (chain == e.chainId) (.revertArgs "PinnedMleVerifierChainMismatch" [adapter, e.chainId, chain])
  let core ← (e.lifecycle.getter adapter .core).mapError (fun _ => invalid)
  require (e.codeLength core != 0) invalid
  let coreChain ← (e.lifecycle.getter core .allowedChainId).mapError
    (fun _ => .revertArgs "InvalidPinnedMleVerifier" [core])
  require (coreChain == e.chainId) (.revertArgs "PinnedMleVerifierChainMismatch" [core, e.chainId, coreChain])
  pure core

structure Deployment where
  treasury : Address
  deployer : Address
  chainId : Nat
  validityAdapter : Address
  withdrawalAdapter : Address
  initial : State

def constructor (e : Environment) (treasury validity withdrawal genesis : Nat) : Result Deployment := do
  require (validity != withdrawal) (.revert "DuplicatePinnedMleVerifier")
  let vc ← requirePinnedVerifier e validity
  let wc ← requirePinnedVerifier e withdrawal
  require (vc != wc && vc != withdrawal && wc != validity) (.revert "DuplicatePinnedMleVerifier")
  let initial := { empty with
    chain := { empty.chain with finalizedRoot := genesis }
    finalizedRoot := if genesis = 0 then empty.finalizedRoot else put empty.finalizedRoot genesis true }
  pure ⟨treasury, e.caller, e.chainId, validity, withdrawal, recordCheckpoint e initial⟩

def registerSettlementManager (e : Environment) (s : State) (manager : Address) :
    Result (State × List Event) := do
  requireDeployer e
  let registered := { s with registeredManager := put s.registeredManager manager true }
  let reply := e.lifecycle.materializerGetter registered manager
  -- Assembly assigns an address: preserve low160 bits of its returned word.
  let materializer := if reply.ok && reply.size == 32 then reply.firstWord % 2 ^ 160 else 0
  let after ← if materializer = 0 then pure registered else do
    require (e.codeLength materializer != 0) (.revert "InvalidChannelExitManager")
    let installed := registered.materializer
    let bound ← if installed = 0 then pure { registered with materializer := materializer } else do
      require (installed == materializer) (.revert "InvalidChannelExitManager")
      pure registered
    e.lifecycle.bindManager bound materializer manager
  pure (after, [.managerRegistered manager])

def setBlockProducer (e : Environment) (s : State) (producer : Address) (allowed : Bool) :
    Result (State × List Event) := do
  require (e.caller == e.deployer || e.caller == s.chain.producerAdmin) (.revert "NotBlockProducerManager")
  pure ({ s with chain := { s.chain with producers := put s.chain.producers producer allowed } },
    [.blockProducerSet producer allowed])

def setBlockProducerAdmin (e : Environment) (s : State) (admin : Address) : Result (State × List Event) := do
  requireDeployer e
  pure ({ s with chain := { s.chain with producerAdmin := admin } }, [.blockProducerAdminSet admin])

def setKzgVerifier (e : Environment) (s : State) (verifier : Address) : Result State := do
  requireDeployer e
  require (s.chain.kzg == 0) (.revert "KzgVerifierAlreadySet")
  require (e.codeLength verifier != 0) (.revert "KzgVerifierNotAContract")
  pure { s with chain := { s.chain with kzg := verifier } }

def canonicalIdentity (identity : Hash) : Bool :=
  ([0,64,128,192] : List Nat).all fun offset => (identity / 2 ^ offset) % u64Limit < goldilocks

def requireValidIdentities (pkG pkB regev recipient : Nat) : Result Unit :=
  require (pkG != 0 && regev != 0 && recipient != 0 &&
    canonicalIdentity pkG && canonicalIdentity pkB && canonicalIdentity regev)
    (.revert "MemberCountOrArrayLenInvalid")

def validateMembers (r : Registration) : Nat → Result Unit
  | 0 => pure ()
  | count + 1 => do
    let index := r.pkGs.length - (count + 1)
    requireValidIdentities (r.pkGs.getD index 0) (r.pkBs.getD index 0)
      (r.regev.getD index 0) (r.recipients.getD index 0)
    require (!(r.pkGs.drop (index + 1)).contains (r.pkGs.getD index 0)) (.revert "MemberPubkeyHashesNotDistinct")
    validateMembers r count

def closeMemberSetCommitment (e : Environment) (count : Nat) (pkGs : List Hash) : Hash :=
  e.hash (.closeMembers 0x494d434d count ((List.range 8).map fun i => if i < count then pkGs.getD i 0 else 0))

def channelRegHashChain (e : Environment) (previous : Hash) (r : Registration) : Hash :=
  let slots := (List.range 8).map fun i =>
    if i < r.pkGs.length then MemberSlot.mk (r.pkGs.getD i 0) (r.pkBs.getD i 0)
      (r.regev.getD i 0) (r.recipients.getD i 0) else ⟨0, 0, 0, 0⟩
  e.hash (.channelRegistration previous r.channel r.bpSlot r.pkGs.length 0 slots)

def calldataIndex (array : List Nat) (index : Nat) : Result Nat :=
  match array[index]? with
  | none => .error (.panic "array index out of bounds")
  | some value => .ok value

/-- General source helper, including arbitrary header/activeCount and checked
array accesses. registerChannel above specializes its validated source domain;
the byte-equivalence link is explicit in HashEncodingAgrees, not extraction. -/
def registrationSlots (activeCount : Nat) (pkGs pkBs regev recipients : List Nat) : Nat → Result (List MemberSlot)
  | 0 => pure []
  | count + 1 => do
    let i := 8 - (count + 1)
    let slot ← if i < activeCount then do
      let pkG ← calldataIndex pkGs i
      let pkB ← calldataIndex pkBs i
      let r ← calldataIndex regev i
      let recipient ← calldataIndex recipients i
      pure (MemberSlot.mk pkG pkB r recipient)
    else pure ⟨0, 0, 0, 0⟩
    let tail ← registrationSlots activeCount pkGs pkBs regev recipients count
    pure (slot :: tail)

def channelRegHashChainRaw (e : Environment) (header : Bytes) (activeCount : Nat)
    (pkGs pkBs regev recipients : List Nat) : Result Hash := do
  let slots ← registrationSlots activeCount pkGs pkBs regev recipients 8
  pure (e.hash (.registrationBytes header slots))

def registerChannel (e : Environment) (s : State) (r : Registration) : Result (State × List Event) := do
  requireDeployer e
  require (r.channel != 0) (.revert "ChannelIdZeroReserved")
  require (r.channel != 0xffffffff) (.revert "ChannelIdBurnReserved")
  require (r.delegates == 0) (.revert "DelegateCountExceedsActive")
  require (s.chain.memberCommitment r.channel == 0) (.revert "ChannelAlreadyRegistered")
  let count := r.pkGs.length
  require (2 ≤ count && count ≤ 8 && r.pkBs.length == count &&
    r.regev.length == count && r.recipients.length == count) (.revert "MemberCountOrArrayLenInvalid")
  require (r.bpSlot < count) (.revert "BpMemberSlotOutOfRange")
  validateMembers r count
  let header := wordBytes 32 s.pendingRegistrationChain ++ wordBytes 4 r.channel ++
    wordBytes 4 r.bpSlot ++ wordBytes 4 count ++ wordBytes 4 0
  let newHash ← channelRegHashChainRaw e header count r.pkGs r.pkBs r.regev r.recipients
  let regCount ← checkedAdd s.registrationCount 1 u64Limit
  let next := { s with
    pendingRegistrationChain := newHash
    registrationCount := regCount
    chain := { s.chain with
      memberCommitment := put s.chain.memberCommitment r.channel (closeMemberSetCommitment e count r.pkGs)
      bpSlot := put s.chain.bpSlot r.channel r.bpSlot
      bpPkG := put s.chain.bpPkG r.channel (r.pkGs.getD r.bpSlot 0) } }
  pure (recordCheckpoint e next, [.channelRegistered s.registrationCount r.channel r.bpSlot r.pkGs r.regev r.recipients
    (e.hash (.identityArray r.pkGs)) (e.hash (.identityArray r.regev)) newHash])

def computeBlockHash (e : Environment) (previous : Hash) (b : SubBlock) (deposits registrations : Hash) : Hash :=
  e.hash (.block previous b deposits registrations)

/-- Loop locals survive callback storage changes; materializer address is captured
once before iteration exactly as source. Own events omit callee log interleaving. -/
def postSubBlocks (e : Environment) (materializer previousDeposits previousRegistrations
    finalDeposits finalRegistrations : Nat) :
    State → Nat → Hash → List SubBlock → Result (State × Nat × Hash × List Event)
  | s, height, previous, [] => pure (s, height, previous, [])
  | s, height, previous, b :: rest => do
    let nextHeight ← checkedAdd height 1 u64Limit
    let callback ← if materializer = 0 then pure s else e.lifecycle.recordPost s materializer b.channelId nextHeight
    let deposits := if rest.isEmpty then finalDeposits else previousDeposits
    let registrations := if rest.isEmpty then finalRegistrations else previousRegistrations
    let hash := computeBlockHash e previous b deposits registrations
    let next := { callback with chain := { callback.chain with
      blockDeposit := put callback.chain.blockDeposit nextHeight deposits
      blockRegistration := put callback.chain.blockRegistration nextHeight registrations } }
    let (after, finalHeight, finalHash, events) ← postSubBlocks e materializer previousDeposits
      previousRegistrations finalDeposits finalRegistrations next nextHeight hash rest
    pure (after, finalHeight, finalHash, .blockPosted nextHeight b.channelId b.keyIds b.txTreeRoot hash :: events)

def postBlock (e : Environment) (s : State) (blocks : List SubBlock)
    (deposits registrations depositCount : Nat) : Result (State × BatchMetadata × List Event) := do
  require (!blocks.isEmpty) (.revert "EmptyBatch")
  let start ← checkedAdd s.chain.blockNumber 1 u64Limit
  let round ← checkedAdd s.chain.round 1 u64Limit
  let incremented := { s with chain := { s.chain with round := round } }
  let (callback, height, hash, events) ← postSubBlocks e incremented.materializer
    s.chain.depositChain s.chain.registrationChain deposits registrations incremented s.chain.blockNumber s.chain.blockHash blocks
  let after := { callback with chain := { callback.chain with
    blockNumber := height, blockHash := hash, blockHashAt := put callback.chain.blockHashAt height hash,
    depositChain := deposits, registrationChain := registrations, processedDeposits := depositCount } }
  let meta := BatchMetadata.mk start height s.chain.blockHash s.chain.depositChain s.chain.round round
    s.chain.processedDeposits s.chain.registrationChain
  pure (after, meta, events)

def submit (e : Environment) (s : State) (proofHash proofLength root : Nat) :
    Result (State × Nat × List Event) := do
  let nextId ← checkedAdd s.chain.nextSubmission 1 u256Limit
  let id := s.chain.nextSubmission
  let allocated := { s with chain := { s.chain with nextSubmission := nextId } }
  let ethBlock := e.blockNumber % u64Limit
  let (callback, commitment) ← e.lifecycle.postCommitment allocated allocated.chain.kzg root ethBlock id
  let submission := Submission.mk commitment e.caller false ethBlock root
  let after := { callback with chain := { callback.chain with submissions := put callback.chain.submissions id submission } }
  pure (after, id, [.submitted id e.caller commitment proofHash proofLength root])

def postBlockAndSubmitInternal (e : Environment) (s : State) (blocks : List SubBlock)
    (proofHash proofLength root deposits registrations depositCount : Nat) : Result (State × List Event) := do
  require (s.chain.producers e.caller || e.caller == s.chain.producerAdmin) (.revert "NotAuthorizedBlockProducer")
  require (e.value == stakeAmount) (.revert "InvalidStakeAmount")
  let (posted, metadata, blockEvents) ← postBlock e s blocks deposits registrations depositCount
  let (submitted, id, submissionEvents) ← submit e posted proofHash proofLength root
  let after := { submitted with chain := { submitted.chain with
    stakes := put submitted.chain.stakes id ⟨e.caller, false⟩
    batches := put submitted.chain.batches id metadata } }
  pure (after, blockEvents ++ submissionEvents)

def postBlockAndSubmitPinned (e : Environment) (s : State) (blocks : List SubBlock)
    (proofHash proofLength root pin : Nat) : Result (State × List Event) := do
  let checkpoint := s.checkpoints pin
  let processed := s.checkpoints (e.hash (.pendingPin s.chain.depositChain s.chain.registrationChain))
  let count := checkpoint.packedCounts / 2 % u64Limit
  let regCount := checkpoint.packedCounts / 2 ^ 65 % u64Limit
  require (checkpoint.packedCounts != 0 && processed.packedCounts / 2 % u64Limit ≤ count &&
    processed.packedCounts / 2 ^ 65 % u64Limit ≤ regCount) (.revert "PendingChainsMoved")
  postBlockAndSubmitInternal e s blocks proofHash proofLength root checkpoint.depositChain checkpoint.registrationChain count

def postBlockAndSubmit (e : Environment) (s : State) (blocks : List SubBlock)
    (proofHash proofLength root pin : Nat) : Result (State × List Event) :=
  guarded s fun locked => do
    require (e.chainId == 31337) (.revert "ReleaseRuntimeUnavailable")
    postBlockAndSubmitPinned e locked blocks proofHash proofLength root pin

def postBlockAndSubmitGuarded (e : Environment) (s : State) (blocks : List SubBlock)
    (proofHash proofLength root pin expectedHeight expectedHash : Nat) : Result (State × List Event) := do
  releaseRuntime e
  guarded s fun locked => do
    require (locked.chain.blockNumber == expectedHeight && locked.chain.blockHash == expectedHash) (.revert "BlockHeadMoved")
    postBlockAndSubmitPinned e locked blocks proofHash proofLength root pin

def computeValidityPIHash (e : Environment) (pis : ValidityPIs) : Hash := e.hash (.validityPis pis)

def mlePublicInputsMatch (inputs : List Nat) (hash : Hash) : Bool :=
  inputs.length == 8 && limbsMatchBytes32 inputs 0 hash

def fullVerify (e : Environment) (s : State) (root : Hash) (pis : ValidityPIs) (proof : Bytes) : Result Bool := do
  require (s.chain.finalizedBlock ≤ pis.finalBlock) (.revert "FinalizedHeightRegression")
  require (pis.initialRoot == s.chain.finalizedRoot) (.revert "InitialStateMismatch")
  require (pis.initialChain == s.chain.blockHashAt pis.initialBlock) (.revert "BlockChainMismatch")
  require (pis.finalChain == s.chain.blockHashAt pis.finalBlock) (.revert "FinalBlockChainMismatch")
  require (pis.finalRoot == root) (.revert "FinalExtCommitmentMismatch")
  let inputs ← (e.verifyCompact e.lifecycle.validityAdapter proof).mapError (fun _ => .revert "MleVerificationFailed")
  require (mlePublicInputsMatch inputs (computeValidityPIHash e pis)) (.revert "ValidityPublicInputsMismatch")
  pure true

def pendingCreditState (s : State) (recipient amount : Nat) : State :=
  { s with pending := put s.pending .native (put (s.pending .native) recipient (s.pending .native recipient + amount)) }

def pendingCredit (s : State) (recipient amount : Nat) : Result State := do
  require (s.pending .native recipient + amount < u256Limit) (.panic "uint256 overflow")
  pure (pendingCreditState s recipient amount)

def deleteStake (s : State) (id : Nat) : State :=
  { s with chain := { s.chain with stakes := put s.chain.stakes id {} } }

def refundStake (s : State) (id : Nat) : Result (State × List Event) := do
  let info := s.chain.stakes id
  let deleted := deleteStake s id
  if info.submitter = 0 || info.spent then pure (deleted, []) else do
    let credited ← pendingCredit deleted info.submitter stakeAmount
    pure (credited, [.withdrawalCredited info.submitter stakeAmount])

def slashStake (e : Environment) (s : State) (id reporter : Nat) : Result (State × List Event) := do
  let info := s.chain.stakes id
  let deleted := deleteStake s id
  if info.submitter = 0 || info.spent then pure (deleted, []) else do
    let rewarded ← pendingCredit deleted reporter fraudReward
    let credited ← pendingCredit rewarded e.lifecycle.fraudTreasury treasuryShare
    pure (credited, [.withdrawalCredited reporter fraudReward, .withdrawalCredited e.lifecycle.fraudTreasury treasuryShare])

def reclaimStake (s : State) (id : Nat) : Result (State × List Event) :=
  guarded s fun locked => do
    let info := locked.chain.stakes id
    require (info.submitter != 0 && !info.spent) (.revert "NothingToReclaim")
    require ((locked.chain.batches id).endBlock ≤ locked.chain.finalizedBlock) (.revert "SubmissionNotYetFinalized")
    let credited ← pendingCredit (deleteStake locked id) info.submitter stakeAmount
    pure (credited, [.withdrawalCredited info.submitter stakeAmount])

def rejectFinalize (s : State) (id reason : Nat) : State × Bool × List Event :=
  (s, false, [.finalizeRejected id reason])

/-- Catch reads four bytes only if returndata has at least four bytes. -/
def firstSelector (bytes : Bytes) : Nat :=
  if bytes.length < 4 then 0 else (bytes.take 4).foldl (fun acc byte => acc * 256 + byte.toNat) 0

def errorSelector (e : Environment) (error : Error) : Nat := firstSelector (e.lifecycle.encodeError error)

def acceptFinality (s : State) (id root height : Nat) : State :=
  { s with
    finalizedRoot := put s.finalizedRoot root true
    chain := { s.chain with
      submissions := put s.chain.submissions id { s.chain.submissions id with finalized := true }
      finalizedRoot := root
      finalizedBlock := height } }

def finalizeBody (e : Environment) (s : State) (id root : Nat) (pis : ValidityPIs) (proof : Bytes) :
    Result (State × Bool × List Event) := do
  let sub := s.chain.submissions id
  if sub.commitment = 0 then return rejectFinalize s id (errorSelector e (.revert "SubmissionNotFound"))
  if sub.finalized then return rejectFinalize s id (errorSelector e (.revert "AlreadyFinalized"))
  if root != sub.stateRoot then return rejectFinalize s id (errorSelector e (.revert "CommitmentMismatch"))
  if pis.finalBlock != (s.chain.batches id).endBlock then
    return rejectFinalize s id (errorSelector e (.revert "ValidityPublicInputsMismatch"))
  let attested ← e.lifecycle.isAttested s s.chain.kzg id sub.commitment (e.hash (.rawBytes proof)) proof.length
  if !attested then return rejectFinalize s id (errorSelector e (.revert "CommitmentMismatch"))
  -- Direct evaluation models the source self STATICCALL's code path; EVM gas,
  -- ABI return decoding and self-call exceptional aborts remain dependencies.
  let verdict := fullVerify e s root pis proof
  match verdict with
  | .error error => return rejectFinalize s id (errorSelector e error)
  | .ok false => return rejectFinalize s id 0
  | .ok true =>
    let accepted := acceptFinality s id root pis.finalBlock
    let (after, refundEvents) ← refundStake accepted id
    pure (after, true, .finalized id root :: refundEvents)

def guardedResult (s : State) (body : State → Result (State × Bool × List Event)) :
    Result (State × Bool × List Event) := do
  let locked ← nonReentrantBefore s
  let (after, answer, events) ← body locked
  pure (nonReentrantAfter after, answer, events)

def finalize (e : Environment) (s : State) (id root : Nat) (pis : ValidityPIs) (proof : Bytes) :
    Result (State × Bool × List Event) :=
  guardedResult s fun locked => finalizeBody e locked id root pis proof

def encodedMleVerdict (e : Environment) (proof : Bytes) (hash : Hash) : Result Nat := do
  if e.lifecycle.gasAtEntry < minVerifyGas then return 3
  let reserve := e.lifecycle.gasAtReserve / 64
  require (reserve ≤ e.lifecycle.gasAtBudget) (.panic "uint256 underflow")
  let budget := e.lifecycle.gasAtBudget - reserve
  match e.lifecycle.classify e.lifecycle.validityAdapter proof hash budget with
  | .ok verdict => pure verdict
  | .error _ =>
    let threshold ← checkedAdd reserve (budget / 8) u256Limit
    pure (if e.lifecycle.gasAfterFailure < threshold then 3 else 2)

def verifyFraud (e : Environment) (s : State) (id root : Nat) (pis : ValidityPIs) (proof : Bytes) : Result Bool := do
  let attested ← e.lifecycle.isAttested s s.chain.kzg id (s.chain.submissions id).commitment
    (e.hash (.rawBytes proof)) proof.length
  if !attested then return false
  if pis.initialRoot != s.chain.finalizedRoot then return false
  if pis.initialChain != s.chain.blockHashAt pis.initialBlock then return false
  if pis.finalChain != s.chain.blockHashAt pis.finalBlock then return false
  if pis.finalRoot != root then return false
  let verdict ← encodedMleVerdict e proof (computeValidityPIHash e pis)
  if verdict = 4 then return false
  require (verdict != 3) (.revert "FraudProofGasStarved")
  require (verdict ≤ 1) (.revert "MleProofUnevaluable")
  pure (verdict == 0)

def rollbackHead (s : State) (meta : BatchMetadata) : State :=
  { s with chain := { s.chain with
    blockHash := meta.previousHash
    blockNumber := if meta.startBlock = 0 then 0 else meta.startBlock - 1
    depositChain := meta.previousDepositChain
    registrationChain := meta.previousRegistrationChain
    round := meta.roundBefore } }

def clearBlockRecords (s : State) (height : Nat) : State :=
  { s with chain := { s.chain with
    blockDeposit := put s.chain.blockDeposit height 0
    blockRegistration := put s.chain.blockRegistration height 0
    blockHashAt := put s.chain.blockHashAt height 0 } }

/-- Structural fuel is the inclusive range length, not a source guard. Captured
materializer and descending height sequence match the source while loop. -/
def rollbackBlocks (e : Environment) (materializer start : Nat) : Nat → State → Result State
  | 0, s => pure s
  | count + 1, s => do
    let height := start + count
    let callback ← if materializer = 0 then pure s else e.lifecycle.rollbackPost s materializer height
    rollbackBlocks e materializer start count (clearBlockRecords callback height)

def rollbackBatch (e : Environment) (s : State) (id : Nat) : Result State := do
  let meta := s.chain.batches id
  if meta.endBlock = 0 && meta.startBlock = 0 then return s
  let rewound := rollbackHead s meta
  let after ← if meta.startBlock ≤ meta.endBlock && meta.endBlock != 0 then
      rollbackBlocks e rewound.materializer meta.startBlock (meta.endBlock - meta.startBlock + 1) rewound
    else pure rewound
  pure { after with chain := { after.chain with processedDeposits := meta.processedBefore } }

def deleteSubmission (s : State) (id : Nat) : State :=
  { s with chain := { s.chain with
    submissions := put s.chain.submissions id {}
    batches := put s.chain.batches id {} } }

def truncateLoop (e : Environment) (target reporter : Nat) : Nat → State → Result (State × List Event)
  | 0, s => pure (s, [])
  | count + 1, s => do
    let id := target + count
    require (!(s.chain.submissions id).finalized) (.revert "AlreadyFinalized")
    let (slashed, stakeEvents) ← slashStake e s id reporter
    let rolled ← rollbackBatch e slashed id
    let (after, events) ← truncateLoop e target reporter count (deleteSubmission rolled id)
    pure (after, stakeEvents ++ events)

def truncateSubmissions (e : Environment) (s : State) (target reporter : Nat) : Result (State × List Event) := do
  let (after, events) ← truncateLoop e target reporter (s.chain.nextSubmission - target) s
  pure ({ after with chain := { after.chain with nextSubmission := target } }, events)

def fraudProofBody (e : Environment) (s : State) (id root : Nat) (pis : ValidityPIs) (proof : Bytes) :
    Result (State × Bool × List Event) := do
  let sub := s.chain.submissions id
  if sub.commitment = 0 then return (s, false, [])
  require (!sub.finalized) (.revert "SubmissionAlreadyFinalized")
  require (s.chain.finalizedBlock < (s.chain.batches id).startBlock) (.revert "SubmissionBeforeFinalizedBlock")
  let deadline ← checkedAdd sub.submittedAt finalizeDeadline u256Limit
  let confirmed ← if deadline < e.blockNumber then pure true else verifyFraud e s id root pis proof
  if !confirmed then return (s, false, [])
  let (after, events) ← truncateSubmissions e s id e.caller
  pure (after, true, events ++ [.fraudConfirmed id e.caller])

def fraudProof (e : Environment) (s : State) (id root : Nat) (pis : ValidityPIs) (proof : Bytes) :
    Result (State × Bool × List Event) :=
  guardedResult s fun locked => fraudProofBody e locked id root pis proof

def attestProofData (e : Environment) (s : State) (id : Nat) (proof sidecar : Bytes) : Result (State × Hash) :=
  e.lifecycle.attest s s.chain.kzg e.self id proof sidecar

def getSubmission (s : State) (id : Nat) : Submission := s.chain.submissions id
def getCommitment (s : State) (id : Nat) : Hash := (s.chain.submissions id).commitment
def isFinalized (s : State) (id : Nat) : Bool := (s.chain.submissions id).finalized

def encodeMemberSlot (slot : MemberSlot) : Bytes :=
  wordBytes 32 slot.pkG ++ wordBytes 32 slot.pkB ++ wordBytes 32 slot.regev ++ wordBytes 20 slot.recipient

def hashPreimage : HashInput → Bytes
  | .deposit previous d => wordBytes 32 previous ++ wordBytes 20 d.depositor ++ wordBytes 32 d.recipient ++
      wordBytes 4 d.token ++ wordBytes 32 d.amount ++ wordBytes 32 d.auxData
  | .pendingPin d r => wordBytes 32 d ++ wordBytes 32 r
  | .withdrawalAuth domain recipient token amount aux => wordBytes 4 domain ++ wordBytes 20 recipient ++
      wordBytes 4 token ++ wordBytes 32 amount ++ wordBytes 32 aux
  | .withdrawalLeaf previous w => wordBytes 32 previous ++ wordBytes 20 w.recipient ++ wordBytes 4 w.token ++
      wordBytes 32 w.amount ++ wordBytes 32 w.nullifier ++ wordBytes 32 w.auxData
  | .withdrawalPis chain prover root height => wordBytes 32 chain ++ wordBytes 20 prover ++ wordBytes 32 root ++ wordBytes 8 height
  | .validityPis p => wordBytes 8 p.initialBlock ++ wordBytes 32 p.initialChain ++ wordBytes 32 p.initialRoot ++
      wordBytes 8 p.finalBlock ++ wordBytes 32 p.finalChain ++ wordBytes 32 p.finalRoot ++ wordBytes 20 p.prover
  | .block previous b deposits registrations => wordBytes 32 previous ++ wordBytes 4 b.channelId ++
      wordBytes 8 b.timestamp ++ b.keyIds.bind (wordBytes 4) ++ wordBytes 32 b.txTreeRoot ++
      wordBytes 32 deposits ++ wordBytes 32 registrations
  | .closeMembers domain count padded => wordBytes 4 domain ++ wordBytes 4 count ++ padded.bind (wordBytes 32)
  | .channelRegistration previous channel bp count delegates slots => wordBytes 32 previous ++ wordBytes 4 channel ++
      wordBytes 4 bp ++ wordBytes 4 count ++ wordBytes 4 delegates ++ slots.bind encodeMemberSlot
  | .registrationBytes header slots => header ++ slots.bind encodeMemberSlot
  | .identityArray identities => identities.bind (wordBytes 32)
  | .rawBytes bytes => bytes

/-- Explicit encoding/Keccak coherence obligation, not collision resistance or
proof soundness. Local storage theorems do not assume this property. -/
def HashEncodingAgrees (e : Environment) (keccak : Bytes → Hash) : Prop :=
  ∀ input, e.hash input = keccak (hashPreimage input)

/-! ## Local theorems; none assumes the desired whole-protocol safety property. -/

theorem failure_rolls_back_storage_and_logs (s : State) (error : Error) :
    commit s (.error error) = (s, []) := rfl

theorem entered_reentry_rejected (s : State) (entered : s.status = 2) :
    nonReentrantBefore s = .error (.revert "ReentrantCall") := by simp [nonReentrantBefore, entered]

theorem guarded_reentry_rejected (s : State) (body : State → Result (State × List Event))
    (entered : s.status = 2) : guarded s body = .error (.revert "ReentrantCall") := by
  simp [guarded, entered_reentry_rejected s entered]

theorem consumed_nullifier_is_used (s : State) (digest : Hash) (w : Withdrawal) :
    (consumedState s digest w).used w.nullifier = true := by simp [consumedState, put]

theorem already_used_withdrawal_rejected (e : Environment) (s : State) (w : Withdrawal)
    (used : s.used w.nullifier = true) :
    consumeWithdrawalGuard e s w = .error (.revert "WithdrawalNullifierUsed") := by
  simp [consumeWithdrawalGuard, require, used]

theorem same_leaf_cannot_be_consumed_again (e : Environment) (s : State) (w : Withdrawal) :
    consumeWithdrawalGuard e (consumedState s (withdrawalAuthDigest e w) w) w =
      .error (.revert "WithdrawalNullifierUsed") := by
  apply already_used_withdrawal_rejected
  exact consumed_nullifier_is_used s _ w

theorem consumed_auth_is_scoped (s : State) (digest : Hash) (w : Withdrawal) (other : Hash)
    (different : other ≠ digest) :
    (consumedState s digest w).authorized other = s.authorized other := by
  by_cases aux : w.auxData = 0 <;> simp [consumedState, put, different, aux]

theorem auth_preimage_excludes_only_nullifier (e : Environment) (w : Withdrawal) (n : Hash) :
    withdrawalAuthDigest e {w with nullifier := n} = withdrawalAuthDigest e w := rfl

theorem credit_conserves_token_value (s : State) (asset : Asset) (recipient amount : Nat)
    (enough : amount ≤ s.escrow asset) :
    (creditState s asset recipient amount).escrow asset + amount = s.escrow asset ∧
    (creditState s asset recipient amount).pending asset recipient = s.pending asset recipient + amount := by
  simp [creditState, put]; omega

theorem credit_frames_other_asset (s : State) (asset other : Asset) (recipient amount : Nat)
    (different : other ≠ asset) :
    (creditState s asset recipient amount).escrow other = s.escrow other ∧
    (creditState s asset recipient amount).pending other = s.pending other := by
  simp [creditState, put, different]

theorem credit_frames_other_recipient (s : State) (asset : Asset) (recipient other amount : Nat)
    (different : other ≠ recipient) :
    (creditState s asset recipient amount).pending asset other = s.pending asset other := by
  simp [creditState, put, different]

theorem successful_credit_is_exact {s after : State} {asset : Asset} {recipient amount : Nat}
    (h : creditEscrow s asset recipient amount = .ok after) :
    after.escrow asset + amount = s.escrow asset ∧
    after.pending asset recipient = s.pending asset recipient + amount := by
  simp only [creditEscrow, require] at h
  split at h <;> simp only [result_bind_ok, result_bind_error] at h
  rename_i enough
  split at h <;> simp at h
  subst after
  exact credit_conserves_token_value s asset recipient amount (of_decide_eq_true enough)

theorem successful_credit_characterization (s after : State) (asset : Asset) (recipient amount : Nat) :
    creditEscrow s asset recipient amount = .ok after ↔
      amount ≤ s.escrow asset ∧ s.pending asset recipient + amount < u256Limit ∧
      after = creditState s asset recipient amount := by
  by_cases enough : amount ≤ s.escrow asset <;>
    by_cases fits : s.pending asset recipient + amount < u256Limit <;>
    simp [creditEscrow, require, enough, fits, eq_comm]

theorem successful_close_credit_characterization (e : Environment) (s after : State)
    (manager index amount : Nat) :
    creditChannelExit e s manager index amount = .ok after ↔
      e.chainId = e.deploymentChainId ∧ e.caller = s.materializer ∧
      creditEscrow s (assetOfToken index) manager amount = .ok after := by
  by_cases chain : e.chainId = e.deploymentChainId <;>
    by_cases caller : e.caller = s.materializer <;>
    by_cases token : index = 0 <;>
    simp [creditChannelExit, releaseRuntime, require, chain, caller, token,
      assetOfToken, creditNativeEscrow, creditTokenEscrow]

theorem successful_close_credit_conserves (e : Environment) (s after : State)
    (manager index amount : Nat) (h : creditChannelExit e s manager index amount = .ok after) :
    after.escrow (assetOfToken index) + amount = s.escrow (assetOfToken index) ∧
    after.pending (assetOfToken index) manager = s.pending (assetOfToken index) manager + amount := by
  exact successful_credit_is_exact ((successful_close_credit_characterization e s after manager index amount).mp h).2.2

theorem successful_close_credit_frames_other_asset (e : Environment) (s after : State)
    (manager index amount : Nat) (other : Asset) (different : other ≠ assetOfToken index)
    (h : creditChannelExit e s manager index amount = .ok after) :
    after.escrow other = s.escrow other ∧ after.pending other = s.pending other := by
  have credited := ((successful_close_credit_characterization e s after manager index amount).mp h).2.2
  have exactState := ((successful_credit_characterization s after (assetOfToken index) manager amount).mp credited).2.2
  rw [exactState]
  exact credit_frames_other_asset s _ other manager amount different

theorem successful_close_credit_frames_other_manager (e : Environment) (s after : State)
    (manager other index amount : Nat) (different : other ≠ manager)
    (h : creditChannelExit e s manager index amount = .ok after) :
    after.pending (assetOfToken index) other = s.pending (assetOfToken index) other := by
  have credited := ((successful_close_credit_characterization e s after manager index amount).mp h).2.2
  have exactState := ((successful_credit_characterization s after (assetOfToken index) manager amount).mp credited).2.2
  rw [exactState]
  exact credit_frames_other_recipient s _ manager other amount different

theorem successful_finish_deposit_record (e : Environment) (s after : State)
    (d : DepositRecord) (events : List Event) (h : finishDeposit e s d = .ok (after, events)) :
    after.depositCount = s.depositCount + 1 ∧
    after.deposits s.depositCount = some d ∧
    after.pendingDepositChain = e.hash (.deposit s.pendingDepositChain d) ∧
    after.escrow = s.escrow := by
  by_cases fits : s.depositCount + 1 < u64Limit
  · simp [finishDeposit, require, fits] at h
    obtain ⟨ha, _⟩ := h
    cases ha
    simp [recordCheckpoint, put]
  · simp [finishDeposit, require, fits] at h

theorem record_checkpoint_binds_live_chains (e : Environment) (s : State) :
    ((recordCheckpoint e s).checkpoints (pendingChainsPin e s)).depositChain = s.pendingDepositChain ∧
    ((recordCheckpoint e s).checkpoints (pendingChainsPin e s)).registrationChain = s.pendingRegistrationChain := by
  simp [recordCheckpoint, put]

theorem deposit_increments_only_selected_escrow (s : State) (asset : Asset) (amount : Nat) :
    (depositEscrowState s asset amount).escrow asset = s.escrow asset + amount ∧
    (depositEscrowState s asset amount).pending = s.pending := by simp [depositEscrowState, put]

theorem deposit_frames_other_asset (s : State) (asset other : Asset) (amount : Nat)
    (different : other ≠ asset) :
    (depositEscrowState s asset amount).escrow other = s.escrow other := by
  simp [depositEscrowState, put, different]

theorem pull_debits_exact_amount (s : State) (asset : Asset) (caller amount : Nat)
    (enough : amount ≤ s.pending asset caller) :
    (pullState s asset caller amount).pending asset caller + amount = s.pending asset caller := by
  simp [pullState, put]; omega

/-- Distinct Manager/recipient addresses cannot consume each other's pending
credit through this storage update. It is NOT a theorem of L2 channel ownership. -/
theorem pull_frames_other_recipient (s : State) (asset : Asset) (caller other amount : Nat)
    (different : other ≠ caller) :
    (pullState s asset caller amount).pending asset other = s.pending asset other := by
  simp [pullState, put, different]

theorem pull_frames_other_asset (s : State) (asset other : Asset) (caller amount : Nat)
    (different : other ≠ asset) :
    (pullState s asset caller amount).pending other = s.pending other := by
  simp [pullState, put, different]

theorem pull_does_not_debit_escrow_again (s : State) (asset : Asset) (caller amount : Nat) :
    (pullState s asset caller amount).escrow = s.escrow := rfl

theorem native_and_erc20_zero_are_distinct : Asset.native ≠ Asset.erc20 0 := by decide

theorem balance_read_requires_success_and_full_word {e : Environment} {s : State}
    {token account value : Nat} (h : tokenBalanceOf e s token account = .ok value) :
    (e.balanceOf s token account).ok = true ∧ 32 ≤ (e.balanceOf s token account).size := by
  simp only [tokenBalanceOf] at h
  split at h <;> try contradiction
  rename_i condition
  simp only [Bool.or_eq_true, Bool.not_eq_true', decide_eq_true_eq, not_or] at condition
  exact ⟨by cases hh : (e.balanceOf s token account).ok <;> simp_all, by omega⟩

theorem withdrawal_pi_requires_seventeen_limbs {e : Environment} {s : State}
    {ws : List Withdrawal} {prover : Address} {proof : Bytes} {block : Nat}
    (h : verifyWithdrawalSet e s ws prover proof = .ok block) :
    ∃ pi, e.verifyCompact e.withdrawalAdapter proof = .ok pi ∧ pi.length = 17 := by
  unfold verifyWithdrawalSet at h
  by_cases nonempty : ws.isEmpty = false
  · simp only [nonempty, Bool.not_false, require, ↓reduceIte, result_bind_ok] at h
    cases hp : e.verifyCompact e.withdrawalAdapter proof with
    | error error => simp [hp, Except.mapError] at h
    | ok pi =>
      refine ⟨pi, rfl, ?_⟩
      by_cases count : pi.length = 17
      · exact count
      · simp [hp, Except.mapError, count] at h
  · cases ws.isEmpty <;> simp_all [require]

/-- The callback frame is local and explicit, not an assumption of the final
conservation theorem. The native call receives the already-debited ledger. -/
theorem native_pull_with_storage_preserving_callback (e : Environment) (s : State) (amount : Nat)
    (positive : amount ≠ 0) (enough : amount ≤ s.pending .native e.caller)
    (callback : e.sendNative (pullState s .native e.caller amount) e.caller amount =
      .ok (pullState s .native e.caller amount)) :
    withdrawBody e s amount = .ok (pullState s .native e.caller amount, []) := by
  simp [withdrawBody, require, positive, enough, callback, Except.mapError]

theorem successful_native_pull_exact_with_callback_frame (e : Environment) (s : State) (amount : Nat)
    (runtime : e.chainId = e.deploymentChainId) (available : s.status ≠ 2)
    (positive : amount ≠ 0) (enough : amount ≤ s.pending .native e.caller)
    (callback : e.sendNative (pullState { s with status := 2 } .native e.caller amount) e.caller amount =
      .ok (pullState { s with status := 2 } .native e.caller amount)) :
    let output := commit s (withdraw e s amount)
    output.1.pending .native e.caller + amount = s.pending .native e.caller ∧
    output.1.escrow = s.escrow ∧ output.1.status = 1 := by
  have body := native_pull_with_storage_preserving_callback e { s with status := 2 } amount positive enough callback
  simp only [withdraw, releaseRuntime, require, runtime, beq_self_eq_true, ↓reduceIte,
    result_bind_ok, guarded, nonReentrantBefore, available]
  simp [body, commit, nonReentrantAfter, pullState, put]
  omega

/-- A native deposit success witness is independent of any invented hash value
or proof-adapter result: there is no external call on this source branch. -/
theorem native_deposit_success_witness (e : Environment)
    (runtime : e.chainId = e.deploymentChainId) (value : e.value = 20) :
    let output := commit empty (deposit e empty 11 0 20 0)
    output.1.escrow .native = 20 ∧ output.1.depositCount = 1 ∧ output.1.status = 1 := by
  simp [commit, deposit, releaseRuntime, require, runtime, value, guarded, nonReentrantBefore,
    depositBody, depositEscrowState, finishDeposit, recordCheckpoint, nonReentrantAfter,
    empty, put, u256Limit, u64Limit]

theorem valid_credit_example :
    creditNativeEscrow (depositEscrowState empty .native 20) 7 8 =
      .ok (creditState (depositEscrowState empty .native 20) .native 7 8) := by rfl

theorem valid_token_credit_example :
    creditTokenEscrow (depositEscrowState empty (.erc20 4) 20) 4 7 8 =
      .ok (creditState (depositEscrowState empty (.erc20 4) 20) (.erc20 4) 7 8) := by rfl

/-- Successful native loop-body witness, after the separate verifier stage.
This does not invent a compact proof or assume the verifier's soundness. -/
theorem native_leaf_credit_success_witness (e : Environment) :
    let initial := depositEscrowState empty .native 20
    let output := commit initial (withdrawLeaves e true 12 initial [⟨7, 0, 8, 9, 0⟩])
    output.1.escrow .native = 12 ∧ output.1.pending .native 7 = 8 ∧ output.1.used 9 = true := by
  simp [commit, withdrawLeaves, withdrawOne, withdrawalAsset, require, consumeWithdrawalGuard, consumedState,
    creditNativeEscrow, creditEscrow, creditState, depositEscrowState, empty, put, u256Limit]

theorem erc20_leaf_credit_success_witness (e : Environment) :
    let initial := { depositEscrowState empty (.erc20 4) 20 with tokenAddress := put empty.tokenAddress 4 99 }
    let output := commit initial (withdrawLeaves e false 12 initial [⟨7, 4, 8, 9, 0⟩])
    output.1.escrow (.erc20 4) = 12 ∧ output.1.pending (.erc20 4) 7 = 8 ∧ output.1.used 9 = true := by
  simp [commit, withdrawLeaves, withdrawOne, withdrawalAsset, require, consumeWithdrawalGuard, consumedState,
    creditTokenEscrow, creditEscrow, creditState, depositEscrowState, empty, put, u256Limit]

theorem normal_exact_pull_leaves_unrelated_credit :
    (pullState (creditState (depositEscrowState empty .native 20) .native 7 8) .native 7 3).pending .native 7 = 5 := by
  decide

/-! ## Source-derived lifecycle and recovery properties -/

theorem full_verify_success_height {e : Environment} {s : State} {root : Nat}
    {pis : ValidityPIs} {proof : Bytes} {answer : Bool}
    (h : fullVerify e s root pis proof = .ok answer) : s.chain.finalizedBlock ≤ pis.finalBlock := by
  by_cases height : s.chain.finalizedBlock ≤ pis.finalBlock
  · exact height
  · simp [fullVerify, require, height] at h

theorem finality_acceptance_retains_historical_root (s : State) (id root height prior : Nat)
    (known : s.finalizedRoot prior = true) : (acceptFinality s id root height).finalizedRoot prior = true := by
  by_cases same : prior = root <;> simp [acceptFinality, put, same, known]

theorem finality_acceptance_records_new_root (s : State) (id root height : Nat) :
    (acceptFinality s id root height).finalizedRoot root = true ∧
    (acceptFinality s id root height).chain.finalizedBlock = height := by
  simp [acceptFinality, put]

theorem pending_credit_characterization (s after : State) (recipient amount : Nat) :
    pendingCredit s recipient amount = .ok after ↔
      s.pending .native recipient + amount < u256Limit ∧ after = pendingCreditState s recipient amount := by
  by_cases fits : s.pending .native recipient + amount < u256Limit <;>
    simp [pendingCredit, require, fits, eq_comm]

theorem stake_credit_does_not_consume_deposit_escrow (s : State) (recipient amount : Nat) :
    (pendingCreditState s recipient amount).escrow = s.escrow := rfl

theorem stake_credit_exact (s : State) (recipient amount : Nat) :
    (pendingCreditState s recipient amount).pending .native recipient = s.pending .native recipient + amount := by
  simp [pendingCreditState, put]

theorem stake_credit_frames_other_recipient (s : State) (recipient other amount : Nat) (different : other ≠ recipient) :
    (pendingCreditState s recipient amount).pending .native other = s.pending .native other := by
  simp [pendingCreditState, put, different]

theorem stake_credit_frames_erc20 (s : State) (recipient amount token : Nat) :
    (pendingCreditState s recipient amount).pending (.erc20 token) = s.pending (.erc20 token) := by
  simp [pendingCreditState, put]

theorem stake_split_conserves_full_bond : fraudReward + treasuryShare = stakeAmount := by decide

theorem slash_alias_recipient_gets_one_bond (s : State) (recipient : Nat) :
    (pendingCreditState (pendingCreditState s recipient fraudReward) recipient treasuryShare).pending .native recipient =
      s.pending .native recipient + stakeAmount := by
  simp [pendingCreditState, put, Nat.add_assoc, stake_split_conserves_full_bond]

def finalityView (s : State) := (s.finalizedRoot, s.chain.finalizedRoot, s.chain.finalizedBlock)

theorem refund_stake_success_shape (s after : State) (id : Nat) (events : List Event)
    (h : refundStake s id = .ok (after, events)) :
    after.chain.stakes id = ({} : StakeInfo) ∧ after.escrow = s.escrow ∧ finalityView after = finalityView s := by
  simp only [refundStake] at h
  split at h
  · simp only [result_pure, Except.ok.injEq, Prod.mk.injEq] at h
    rcases h with ⟨ha, _⟩
    cases ha
    simp [deleteStake, put, finalityView]
  · cases credit : pendingCredit (deleteStake s id) (s.chain.stakes id).submitter stakeAmount with
    | error err => simp [credit] at h
    | ok credited =>
      have exactState := ((pending_credit_characterization _ _ _ _).mp credit).2
      simp [credit] at h
      rcases h with ⟨ha, _⟩
      cases ha
      rw [exactState]
      simp [pendingCreditState, deleteStake, put, finalityView]

theorem refunded_entry_cannot_refund_again (s after : State) (id : Nat) (events : List Event)
    (h : refundStake s id = .ok (after, events)) :
    refundStake after id = .ok (deleteStake after id, []) := by
  have cleared := (refund_stake_success_shape s after id events h).1
  simp [refundStake, cleared]

/-- This projection retains all custody/live records and permanent finality.
Posting/rollback helpers are allowed to alter only the omitted transient chain
fields. A boundary callback frame is a local storage obligation, NOT a global
entitlement or solvency axiom. It can be discharged by composing the satellite. -/
def protectedView (s : State) : State :=
  { s with chain := { finalizedRoot := s.chain.finalizedRoot, finalizedBlock := s.chain.finalizedBlock } }

def RollbackCallbackFrame (e : Environment) : Prop :=
  ∀ s target height after, e.lifecycle.rollbackPost s target height = .ok after → protectedView after = protectedView s

theorem clear_block_preserves_protected_state (s : State) (height : Nat) :
    protectedView (clearBlockRecords s height) = protectedView s := rfl

theorem rollback_head_preserves_protected_state (s : State) (meta : BatchMetadata) :
    protectedView (rollbackHead s meta) = protectedView s := rfl

theorem rollback_blocks_preserve_protected_state (e : Environment) (frame : RollbackCallbackFrame e)
    (target start count : Nat) (s after : State)
    (h : rollbackBlocks e target start count s = .ok after) : protectedView after = protectedView s := by
  induction count generalizing s after with
  | zero => simp [rollbackBlocks] at h; cases h; rfl
  | succ count ih =>
    by_cases absent : target = 0
    · simp [rollbackBlocks, absent] at h
      rw [absent] at ih
      exact (ih _ _ h).trans (clear_block_preserves_protected_state s _)
    · cases callback : e.lifecycle.rollbackPost s target (start + count) with
      | error err => simp [rollbackBlocks, absent, callback] at h
      | ok next =>
        simp [rollbackBlocks, absent, callback] at h
        exact (ih _ _ h).trans ((clear_block_preserves_protected_state next _).trans (frame _ _ _ _ callback))

theorem rollback_batch_preserves_protected_state (e : Environment) (frame : RollbackCallbackFrame e)
    (s after : State) (id : Nat) (h : rollbackBatch e s id = .ok after) : protectedView after = protectedView s := by
  simp only [rollbackBatch] at h
  split at h
  · simp at h; cases h; rfl
  · split at h
    · cases loop : rollbackBlocks e (rollbackHead s (s.chain.batches id)).materializer
        (s.chain.batches id).startBlock ((s.chain.batches id).endBlock - (s.chain.batches id).startBlock + 1)
        (rollbackHead s (s.chain.batches id)) with
      | error err => simp [loop] at h
      | ok next =>
        simp [loop] at h
        cases h
        exact (rollback_blocks_preserve_protected_state e frame _ _ _ _ _ loop).trans
          (rollback_head_preserves_protected_state s _)
    · simp at h
      cases h
      rfl

theorem rollback_preserves_later_deposit_chain (e : Environment) (frame : RollbackCallbackFrame e)
    (s after : State) (id : Nat) (h : rollbackBatch e s id = .ok after) :
    after.pendingDepositChain = s.pendingDepositChain ∧ after.deposits = s.deposits ∧ after.escrow = s.escrow := by
  have framed := rollback_batch_preserves_protected_state e frame s after id h
  have a := congrArg State.pendingDepositChain framed
  have b := congrArg State.deposits framed
  have c := congrArg State.escrow framed
  exact ⟨a, b, c⟩

theorem rollback_preserves_historical_finality (e : Environment) (frame : RollbackCallbackFrame e)
    (s after : State) (id : Nat) (h : rollbackBatch e s id = .ok after) : finalityView after = finalityView s := by
  have framed := rollback_batch_preserves_protected_state e frame s after id h
  have kept := congrArg finalityView framed
  exact kept

theorem finalize_body_acceptance_receipt (e : Environment) (s after : State) (id root : Nat)
    (pis : ValidityPIs) (proof : Bytes) (events : List Event)
    (h : finalizeBody e s id root pis proof = .ok (after, true, events)) :
    fullVerify e s root pis proof = .ok true ∧
    ∃ refundEvents, refundStake (acceptFinality s id root pis.finalBlock) id = .ok (after, refundEvents) := by
  simp only [finalizeBody] at h
  split at h <;> try simp [rejectFinalize] at h
  split at h <;> try simp [rejectFinalize] at h
  split at h <;> try simp [rejectFinalize] at h
  split at h <;> try simp [rejectFinalize] at h
  cases attestation : e.lifecycle.isAttested s s.chain.kzg id (s.chain.submissions id).commitment
      (e.hash (.rawBytes proof)) proof.length with
  | error err => simp [attestation] at h
  | ok attested =>
    cases attested with
    | false => simp [attestation, rejectFinalize] at h
    | true =>
      simp only [attestation, result_bind_ok, Bool.not_true, Bool.false_eq_true, ↓reduceIte] at h
      cases verified : fullVerify e s root pis proof with
      | error err => simp [verified, rejectFinalize] at h
      | ok answer =>
        cases answer with
        | false => simp [verified, rejectFinalize] at h
        | true =>
          refine ⟨rfl, ?_⟩
          cases refunded : refundStake (acceptFinality s id root pis.finalBlock) id with
          | error err => simp [verified, refunded] at h
          | ok pair =>
            rcases pair with ⟨next, refundEvents⟩
            simp [verified, refunded] at h
            rcases h with ⟨same, _⟩
            cases same
            exact ⟨refundEvents, rfl⟩

theorem successful_finalize_body_monotone_and_historical (e : Environment) (s after : State) (id root : Nat)
    (pis : ValidityPIs) (proof : Bytes) (events : List Event)
    (h : finalizeBody e s id root pis proof = .ok (after, true, events)) :
    s.chain.finalizedBlock ≤ after.chain.finalizedBlock ∧
    after.finalizedRoot root = true ∧ (∀ prior, s.finalizedRoot prior = true → after.finalizedRoot prior = true) := by
  obtain ⟨verified, refundEvents, refunded⟩ := finalize_body_acceptance_receipt e s after id root pis proof events h
  have height := full_verify_success_height verified
  have frame := (refund_stake_success_shape _ _ id refundEvents refunded).2.2
  have heights := congrArg (fun v => v.2.2) frame
  have roots := congrArg (fun v => v.1) frame
  change after.chain.finalizedBlock = pis.finalBlock at heights
  change after.finalizedRoot = (acceptFinality s id root pis.finalBlock).finalizedRoot at roots
  refine ⟨by omega, ?_, ?_⟩
  · rw [roots]
    exact (finality_acceptance_records_new_root s id root pis.finalBlock).1
  · intro prior known
    rw [roots]
    exact finality_acceptance_retains_historical_root s id root pis.finalBlock prior known

theorem finalize_body_false_retains_state (e : Environment) (s after : State) (id root : Nat)
    (pis : ValidityPIs) (proof : Bytes) (events : List Event)
    (h : finalizeBody e s id root pis proof = .ok (after, false, events)) : after = s := by
  simp only [finalizeBody] at h
  split at h
  · simp [rejectFinalize] at h; exact h.1.symm
  split at h
  · simp [rejectFinalize] at h; exact h.1.symm
  split at h
  · simp [rejectFinalize] at h; exact h.1.symm
  split at h
  · simp [rejectFinalize] at h; exact h.1.symm
  cases attestation : e.lifecycle.isAttested s s.chain.kzg id (s.chain.submissions id).commitment
      (e.hash (.rawBytes proof)) proof.length with
  | error err => simp [attestation] at h
  | ok attested =>
    cases attested with
    | false => simp [attestation, rejectFinalize] at h; exact h.1.symm
    | true =>
      simp only [attestation, result_bind_ok, Bool.not_true, Bool.false_eq_true, ↓reduceIte] at h
      cases verified : fullVerify e s root pis proof with
      | error err => simp [verified, rejectFinalize] at h; exact h.1.symm
      | ok answer =>
        cases answer with
        | false => simp [verified, rejectFinalize] at h; exact h.1.symm
        | true =>
          cases refunded : refundStake (acceptFinality s id root pis.finalBlock) id with
          | error err => simp [verified, refunded] at h
          | ok pair => rcases pair with ⟨next, refundEvents⟩; simp [verified, refunded] at h

theorem guarded_result_receipt (s after : State) (body : State → Result (State × Bool × List Event))
    (answer : Bool) (events : List Event) (h : guardedResult s body = .ok (after, answer, events)) :
    ∃ next, body { s with status := 2 } = .ok (next, answer, events) ∧ after = nonReentrantAfter next := by
  by_cases entered : s.status = 2
  · simp [guardedResult, nonReentrantBefore, entered] at h
  · simp only [guardedResult, nonReentrantBefore, entered, ↓reduceIte, result_bind_ok] at h
    cases result : body { s with status := 2 } with
    | error err => simp [result] at h
    | ok pair =>
      rcases pair with ⟨next, actualAnswer, actualEvents⟩
      simp [result] at h
      rcases h with ⟨hs, ha, he⟩
      cases ha
      cases he
      exact ⟨next, rfl, hs.symm⟩

theorem finalize_preserves_historical_roots_and_height (e : Environment) (s after : State) (id root : Nat)
    (pis : ValidityPIs) (proof : Bytes) (answer : Bool) (events : List Event)
    (h : finalize e s id root pis proof = .ok (after, answer, events)) :
    s.chain.finalizedBlock ≤ after.chain.finalizedBlock ∧
    (∀ prior, s.finalizedRoot prior = true → after.finalizedRoot prior = true) := by
  obtain ⟨next, body, ha⟩ := guarded_result_receipt s after _ answer events h
  cases ha
  cases answer with
  | false =>
    have same := finalize_body_false_retains_state e _ next id root pis proof events body
    cases same
    exact ⟨Nat.le_refl _, fun _ known => known⟩
  | true =>
    have safe := successful_finalize_body_monotone_and_historical e _ next id root pis proof events body
    exact ⟨safe.1, safe.2.2⟩

/-- A temporal closure of actual finalize and rollback receipts. This theorem
does not smuggle an arbitrary "safe transition" into the trace: its two steps
are the executable functions above. Other entrypoint families need their own
closure lemmas before inclusion; the map does not call this full-system safety. -/
inductive FinalityRecoveryTrace (e : Environment) : State → State → Prop
  | refl (s) : FinalityRecoveryTrace e s s
  | finalizeStep {initial s after} (prior : FinalityRecoveryTrace e initial s)
      (id root : Nat) (pis : ValidityPIs) (proof : Bytes) (answer : Bool) (events : List Event)
      (receipt : finalize e s id root pis proof = .ok (after, answer, events)) : FinalityRecoveryTrace e initial after
  | rollbackStep {initial s after} (prior : FinalityRecoveryTrace e initial s) (id : Nat)
      (receipt : rollbackBatch e s id = .ok after) : FinalityRecoveryTrace e initial after

theorem finality_recovery_trace_is_monotone (e : Environment) (frame : RollbackCallbackFrame e)
    (initial after : State) (trace : FinalityRecoveryTrace e initial after) :
    initial.chain.finalizedBlock ≤ after.chain.finalizedBlock ∧
    (∀ root, initial.finalizedRoot root = true → after.finalizedRoot root = true) := by
  induction trace with
  | refl => exact ⟨Nat.le_refl _, fun _ h => h⟩
  | finalizeStep _prior id root pis proof answer events receipt ih =>
    have localStep := finalize_preserves_historical_roots_and_height e _ _ id root pis proof answer events receipt
    exact ⟨Nat.le_trans ih.1 localStep.1, fun old known => localStep.2 old (ih.2 old known)⟩
  | rollbackStep _prior id receipt ih =>
    have frameEq := rollback_preserves_historical_finality e frame _ _ id receipt
    have roots := congrArg (fun v => v.1) frameEq
    have heights := congrArg (fun v => v.2.2) frameEq
    dsimp [finalityView] at roots heights
    constructor
    · rw [heights]; exact ih.1
    · intro old known
      rw [roots]
      exact ih.2 old known

theorem validity_preimage_has_exact_width (pis : ValidityPIs) :
    (hashPreimage (.validityPis pis)).length = 164 := by simp [hashPreimage, wordBytes]; decide

theorem withdrawal_leaf_preimage_has_exact_width (previous : Hash) (w : Withdrawal) :
    (hashPreimage (.withdrawalLeaf previous w)).length = 152 := by simp [hashPreimage, wordBytes]; decide

theorem deposit_preimage_has_exact_width (previous : Hash) (d : DepositRecord) :
    (hashPreimage (.deposit previous d)).length = 152 := by simp [hashPreimage, wordBytes]; decide

theorem partial_auth_preimage_has_exact_width (w : Withdrawal) :
    (hashPreimage (.withdrawalAuth ipw2Domain w.recipient w.token w.amount w.auxData)).length = 92 := by
  simp [hashPreimage, wordBytes]; decide

theorem consume_success_is_exact (e : Environment) (s after : State) (w : Withdrawal)
    (h : consumeWithdrawalGuard e s w = .ok after) : after = consumedState s (withdrawalAuthDigest e w) w := by
  cases used : s.used w.nullifier <;>
    by_cases aux : w.auxData = 0 <;>
    cases auth : s.authorized (withdrawalAuthDigest e w) <;>
    simp [consumeWithdrawalGuard, require, used, aux, auth] at h <;> exact h.symm

theorem withdraw_one_receipt (e : Environment) (native : Bool) (s after : State) (w : Withdrawal)
    (h : withdrawOne e native s w = .ok after) :
    ∃ consumed, consumeWithdrawalGuard e s w = .ok consumed ∧
      creditEscrow consumed (withdrawalAsset native w) w.recipient w.amount = .ok after := by
  simp only [withdrawOne] at h
  cases native with
  | true =>
    simp only [↓reduceIte] at h
    by_cases token : w.token = 0
    · simp [require, token] at h
      cases consumed : consumeWithdrawalGuard e s w with
      | error err => simp [consumed] at h
      | ok next => exact ⟨next, rfl, by simpa [consumed] using h⟩
    · simp [require, token] at h
  | false =>
    simp only [Bool.false_eq_true, ↓reduceIte] at h
    by_cases token : w.token = 0
    · simp [require, token] at h
    · by_cases registered : s.tokenAddress w.token = 0
      · simp [require, token, registered] at h
      · simp [require, token, registered] at h
        cases consumed : consumeWithdrawalGuard e s w with
        | error err => simp [consumed] at h
        | ok next => exact ⟨next, rfl, by simpa [consumed] using h⟩

def leafAmount (native : Bool) (asset : Asset) (w : Withdrawal) : Nat :=
  if asset = withdrawalAsset native w then w.amount else 0

def leafCredit (native : Bool) (asset : Asset) (recipient : Nat) (w : Withdrawal) : Nat :=
  if asset = withdrawalAsset native w ∧ recipient = w.recipient then w.amount else 0

theorem withdraw_one_accounts_exactly (e : Environment) (native : Bool) (s after : State) (w : Withdrawal)
    (asset : Asset) (recipient : Nat) (h : withdrawOne e native s w = .ok after) :
    after.escrow asset + leafAmount native asset w = s.escrow asset ∧
    after.pending asset recipient = s.pending asset recipient + leafCredit native asset recipient w := by
  obtain ⟨consumed, hc, credited⟩ := withdraw_one_receipt e native s after w h
  have consumedEq := consume_success_is_exact e s consumed w hc
  obtain ⟨enough, _, exactState⟩ := (successful_credit_characterization _ _ _ _ _).mp credited
  rw [exactState, consumedEq]
  rw [consumedEq] at enough
  by_cases selected : asset = withdrawalAsset native w <;>
    by_cases payee : recipient = w.recipient <;>
    simp [creditState, consumedState, put, leafAmount, leafCredit, selected, payee] at * <;> omega

def setAmount (native : Bool) (asset : Asset) : List Withdrawal → Nat
  | [] => 0
  | w :: rest => leafAmount native asset w + setAmount native asset rest

def setCredit (native : Bool) (asset : Asset) (recipient : Nat) : List Withdrawal → Nat
  | [] => 0
  | w :: rest => leafCredit native asset recipient w + setCredit native asset recipient rest

theorem withdrawal_loop_conserves_each_token (e : Environment) (native : Bool) (block : Nat)
    (s after : State) (ws : List Withdrawal) (events : List Event) (asset : Asset) (recipient : Nat)
    (h : withdrawLeaves e native block s ws = .ok (after, events)) :
    after.escrow asset + setAmount native asset ws = s.escrow asset ∧
    after.pending asset recipient = s.pending asset recipient + setCredit native asset recipient ws := by
  induction ws generalizing s after events with
  | nil =>
    simp [withdrawLeaves] at h
    rcases h with ⟨same, _⟩
    cases same
    simp [setAmount, setCredit]
  | cons w rest ih =>
    cases one : withdrawOne e native s w with
    | error err => simp [withdrawLeaves, one] at h
    | ok credited =>
      have head := withdraw_one_accounts_exactly e native s credited w asset recipient one
      cases tail : withdrawLeaves e native block credited rest with
      | error err => simp [withdrawLeaves, one, tail] at h
      | ok pair =>
        rcases pair with ⟨next, tailEvents⟩
        simp [withdrawLeaves, one, tail] at h
        rcases h with ⟨same, _⟩
        cases same
        have remainder := ih credited after tailEvents tail
        simp only [setAmount, setCredit]
        constructor <;> omega

theorem withdrawal_loop_no_other_token_consumption (e : Environment) (native : Bool) (block : Nat)
    (s after : State) (ws : List Withdrawal) (events : List Event) (asset : Asset)
    (notInSet : setAmount native asset ws = 0)
    (h : withdrawLeaves e native block s ws = .ok (after, events)) : after.escrow asset = s.escrow asset := by
  have accounting := (withdrawal_loop_conserves_each_token e native block s after ws events asset 0 h).1
  simpa [notInSet] using accounting

theorem withdrawal_loop_no_other_recipient_credit (e : Environment) (native : Bool) (block : Nat)
    (s after : State) (ws : List Withdrawal) (events : List Event) (asset : Asset) (recipient : Nat)
    (notInSet : setCredit native asset recipient ws = 0)
    (h : withdrawLeaves e native block s ws = .ok (after, events)) :
    after.pending asset recipient = s.pending asset recipient := by
  have accounting := (withdrawal_loop_conserves_each_token e native block s after ws events asset recipient h).2
  simpa [notInSet] using accounting

end Zkp.Implementation.RollupValue
