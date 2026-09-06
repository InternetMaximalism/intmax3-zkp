import Std

/-!
# IntmaxRollup selected value paths

Manual source-oriented translation of the deposit, withdrawal-set, authorization,
close-credit and exact pull paths in IntmaxRollup.sol (2353 lines, runtime 05ec7ae).
The accompanying full-source partition explicitly marks the remaining methods
untranslated. This is NOT an extracted Solidity/EVM or full Rollup proof.

Native escrow and ERC20 index zero are distinct storage locations. Escrow is
POOLED, not channel-scoped. The proved isolation is token/recipient ledger
framing, not ownership of pooled collateral or proof soundness. In particular,
the source comment saying the global ceiling alone prevents cross-channel theft
is not promoted to a theorem. Entitlement depends on the actual pinned withdrawal
proof and the bound materializer/Manager protocol, modeled as dependencies.

Nat values denote canonical unsigned ABI/getter values; all source additions,
subtractions, the uint64 deposit counter, and the explicit uint64 PI cast are
modeled. Returned withdrawal root limbs are MASKED by the source; only the
pis-hash comparison is strict. No nonexistent u63 check is inserted at pi[16].

External token/native calls receive the exact pre-call state and typed request,
and may return callback-mutated storage. They are NOT assumed harmless. The lock
is visible at those calls and rejects guarded reentry; unguarded calls are NOT
universally excluded. Local accounting theorems cover internal updates. Any
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

def empty : State :=
  ⟨fun _ => 0, fun _ _ => 0, fun _ => 0, fun _ => false, fun _ => false,
   fun _ => false, 0, 1, 0, 0, 0, 0, fun _ => none,
   fun _ => ⟨0, 0, 0⟩, fun _ => false⟩

inductive Event where
  | tokenRegistered (token address : Nat)
  | authorized (digest manager : Nat)
  | deposited (index : Nat) (record : DepositRecord) (newHash : Hash)
  | nativeWithdrawn (recipient amount nullifier blockNumber : Nat)
  | erc20Withdrawn (recipient token amount nullifier blockNumber : Nat)
  | tokenWithdrawalClaimed (recipient token amount : Nat)
  deriving DecidableEq, Repr

inductive HashInput where
  | deposit (previous : Hash) (record : DepositRecord)
  | pendingPin (depositChain registrationChain : Hash)
  | withdrawalAuth (domain : Nat) (recipient token amount auxData : Nat)
  | withdrawalLeaf (previous : Hash) (leaf : Withdrawal)
  | withdrawalPis (chain prover root blockNumber : Nat)
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

def withdrawLeaves (e : Environment) (native : Bool) (block : Nat) :
    State → List Withdrawal → Result (State × List Event)
  | s, [] => pure (s, [])
  | s, w :: ws => do
    if native then require (w.token == 0) (.revert "WithdrawalNotEthToken")
    else
      require (w.token != 0) (.revert "WithdrawalNotErc20Token")
      require (s.tokenAddress w.token != 0) (.revert "TokenIndexNotRegistered")
    let consumed ← consumeWithdrawalGuard e s w
    let credited ← if native then creditNativeEscrow consumed w.recipient w.amount
      else creditTokenEscrow consumed w.token w.recipient w.amount
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
  simp [commit, withdrawLeaves, require, consumeWithdrawalGuard, consumedState,
    creditNativeEscrow, creditEscrow, creditState, depositEscrowState, empty, put, u256Limit]

theorem erc20_leaf_credit_success_witness (e : Environment) :
    let initial := { depositEscrowState empty (.erc20 4) 20 with tokenAddress := put empty.tokenAddress 4 99 }
    let output := commit initial (withdrawLeaves e false 12 initial [⟨7, 4, 8, 9, 0⟩])
    output.1.escrow (.erc20 4) = 12 ∧ output.1.pending (.erc20 4) 7 = 8 ∧ output.1.used 9 = true := by
  simp [commit, withdrawLeaves, require, consumeWithdrawalGuard, consumedState,
    creditTokenEscrow, creditEscrow, creditState, depositEscrowState, empty, put, u256Limit]

theorem normal_exact_pull_leaves_unrelated_credit :
    (pullState (creditState (depositEscrowState empty .native 20) .native 7 8) .native 7 3).pending .native 7 = 5 := by
  decide

end Zkp.Implementation.RollupValue
