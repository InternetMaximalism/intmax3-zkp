import Std

/-!
# Source-oriented SafeERC20 translation

Runtime parent 05ec7ae (unchanged at acfaa78), contracts/src/SafeERC20.sol:1–50.
This file translates the interface, both encodeCall wrappers, short-circuit
evaluation and the actual canonical ABI bool decoder. It is NOT an extracted
EVM semantics. The typed call below is the input to abi.encodeCall; correct
selector/argument serialization and CALL execution are explicit dependencies.

Solidity bool decoding on a nonempty >=32-byte result accepts only the first
word 0 or 1; a different word REVERTS during abi.decode, not with TokenCallFailed.
Trailing bytes are ignored. Unsuccessful CALL short-circuits before decoding.
The helper deliberately does not measure balances or prevent reentrancy.
No theorem below concludes token movement from the helper's accepted result.
The caller must validate the token/registry, exact relevant balance deltas and
transaction atomicity. Existing code at registration is not a theorem that an
arbitrary external token remains honest or behaves like a standard ERC-20.
-/

namespace Zkp.Implementation.SafeERC20

abbrev Address := Fin (2 ^ 160)
abbrev Amount := Fin (2 ^ 256)
abbrev Byte := Fin 256

/-- IERC20:13–17, typed inputs prior to ABI encoding, not an invented transfer. -/
inductive TokenRequest where
  | transfer (to : Address) (amount : Amount)
  | transferFrom (sender to : Address) (amount : Amount)
  | balanceOf (account : Address)
  deriving DecidableEq, Repr

structure Call where
  target : Address
  request : TokenRequest
  deriving DecidableEq, Repr

structure CallResult where
  ok : Bool
  returndata : List Byte
  deriving DecidableEq, Repr

/-- Big-endian memory word load of at most the first 32 return bytes. -/
def decodeBE (bytes : List Byte) : Nat :=
  bytes.foldl (fun word byte => word * 256 + byte.val) 0

def firstWord (ret : List Byte) : Nat := decodeBE (ret.take 32)

inductive Result where
  | accepted
  | tokenCallFailed
  | abiDecodeReverted
  deriving DecidableEq, Repr

/-- Source:38–48. Preserve the two different revert causes and short-circuiting. -/
def callTokenResult (r : CallResult) : Result :=
  if !r.ok then .tokenCallFailed
  else if r.returndata.length = 0 then .accepted
  else if r.returndata.length < 32 then .tokenCallFailed
  else if firstWord r.returndata = 0 then .tokenCallFailed
  else if firstWord r.returndata = 1 then .accepted
  else .abiDecodeReverted

/-- Source:30–32. Neither the recipient nor the amount is masked or replaced. -/
def safeTransferCall (token to : Address) (amount : Amount) : Call :=
  ⟨token, .transfer to amount⟩

/-- Source:34–36. The explicit from/to ordering is part of the ABI contract. -/
def safeTransferFromCall (token sender to : Address) (amount : Amount) : Call :=
  ⟨token, .transferFrom sender to amount⟩

abbrev ExecuteCall := Call → CallResult

def safeTransfer (execute : ExecuteCall) (token to : Address) (amount : Amount) : Result :=
  callTokenResult (execute (safeTransferCall token to amount))

def safeTransferFrom (execute : ExecuteCall) (token sender to : Address)
    (amount : Amount) : Result :=
  callTokenResult (execute (safeTransferFromCall token sender to amount))

theorem transfer_arguments_preserved (token to : Address) (amount : Amount) :
    (safeTransferCall token to amount).target = token ∧
    (safeTransferCall token to amount).request = .transfer to amount := by
  exact ⟨rfl, rfl⟩

theorem transferFrom_arguments_preserved (token sender to : Address) (amount : Amount) :
    (safeTransferFromCall token sender to amount).target = token ∧
    (safeTransferFromCall token sender to amount).request = .transferFrom sender to amount := by
  exact ⟨rfl, rfl⟩

theorem failed_call_never_decodes (ret : List Byte) :
    callTokenResult ⟨false, ret⟩ = .tokenCallFailed := by
  simp [callTokenResult]

theorem successful_empty_return_accepted :
    callTokenResult ⟨true, []⟩ = .accepted := by
  simp [callTokenResult]

theorem short_nonempty_return_rejected {ret : List Byte}
    (positive : 0 < ret.length) (short : ret.length < 32) :
    callTokenResult ⟨true, ret⟩ = .tokenCallFailed := by
  simp [callTokenResult, Nat.ne_of_gt positive, short]

theorem false_word_rejected {ret : List Byte} (enough : 32 ≤ ret.length)
    (word : firstWord ret = 0) :
    callTokenResult ⟨true, ret⟩ = .tokenCallFailed := by
  have nonempty : ret.length ≠ 0 := by omega
  simp [callTokenResult, nonempty, Nat.not_lt.mpr enough, word]

theorem true_word_accepted {ret : List Byte} (enough : 32 ≤ ret.length)
    (word : firstWord ret = 1) :
    callTokenResult ⟨true, ret⟩ = .accepted := by
  have nonempty : ret.length ≠ 0 := by omega
  simp [callTokenResult, nonempty, Nat.not_lt.mpr enough, word]

theorem noncanonical_bool_reverts {ret : List Byte} (enough : 32 ≤ ret.length)
    (notFalse : firstWord ret ≠ 0) (notTrue : firstWord ret ≠ 1) :
    callTokenResult ⟨true, ret⟩ = .abiDecodeReverted := by
  have nonempty : ret.length ≠ 0 := by omega
  simp [callTokenResult, nonempty, Nat.not_lt.mpr enough, notFalse, notTrue]

theorem accepted_iff_success_and_empty_or_true (r : CallResult) :
    callTokenResult r = .accepted ↔
    r.ok = true ∧ (r.returndata.length = 0 ∨
      (32 ≤ r.returndata.length ∧ firstWord r.returndata = 1)) := by
  unfold callTokenResult
  cases hok : r.ok
  · simp [hok]
  · simp only [hok, Bool.not_true, Bool.false_eq_true, ↓reduceIte, true_and]
    by_cases empty : r.returndata.length = 0
    · simp [empty]
    · simp only [empty, ↓reduceIte, false_or]
      by_cases short : r.returndata.length < 32
      · simp [short, Nat.not_le.mpr short]
      · simp only [short, ↓reduceIte, Nat.le_of_not_lt short, true_and]
        by_cases zero : firstWord r.returndata = 0
        · simp [zero]
        · simp [zero]

theorem accepted_requires_success {r : CallResult} (h : callTokenResult r = .accepted) :
    r.ok = true := (accepted_iff_success_and_empty_or_true r).mp h |>.1

theorem transfer_success_has_exact_call (execute : ExecuteCall)
    (token to : Address) (amount : Amount)
    (h : safeTransfer execute token to amount = .accepted) :
    (execute ⟨token, .transfer to amount⟩).ok = true := by
  exact accepted_requires_success h

theorem transferFrom_success_has_exact_call (execute : ExecuteCall)
    (token sender to : Address) (amount : Amount)
    (h : safeTransferFrom execute token sender to amount = .accepted) :
    (execute ⟨token, .transferFrom sender to amount⟩).ok = true := by
  exact accepted_requires_success h

theorem calldata_kinds_are_distinct (to sender : Address) (amount : Amount) :
    TokenRequest.transfer to amount ≠ TokenRequest.transferFrom sender to amount := by
  intro h
  cases h

def zeroByte : Byte := ⟨0, by decide⟩
def oneByte : Byte := ⟨1, by decide⟩
def twoByte : Byte := ⟨2, by decide⟩

theorem example_canonical_true :
    callTokenResult ⟨true, List.replicate 31 zeroByte ++ [oneByte]⟩ = .accepted := by
  decide

theorem example_true_with_trailing_data :
    callTokenResult ⟨true, List.replicate 31 zeroByte ++ [oneByte, twoByte]⟩ = .accepted := by
  decide

theorem example_noncanonical_bool_reverts :
    callTokenResult ⟨true, List.replicate 31 zeroByte ++ [twoByte]⟩ = .abiDecodeReverted := by
  decide

theorem example_failed_call_short_circuits_invalid_bool :
    callTokenResult ⟨false, List.replicate 31 zeroByte ++ [twoByte]⟩ = .tokenCallFailed := by
  decide

end Zkp.Implementation.SafeERC20
