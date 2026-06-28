import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes
import Zkp.Core.Merkle
import Zkp.Core.U256

/-
  Spend authorization circuit  — CRITICAL (solvency)
  ==================================================

  Source: `src/circuits/balance/spend_circuit.rs`

  ## Protocol role

  Proves a user may SEND a tx of up to `MAX_NUM_TRANSFERS_PER_TX`
  (= 2^6 = 64) transfers, by deducting each transfer's amount from the
  sender's asset tree and committing the resulting private-state
  transition. Its public inputs (`prev/new_private_commitment`, `tx`,
  `is_valid`) are exactly what `TxSettlement` later binds to.

  The single most important property: **solvency** — a sender cannot
  send more than they hold. This is enforced per transfer by the
  underflow-rejecting `U256Target::sub` (see `U256.SubSpec`).

  ## Constraint inventory (spend_circuit.rs:260-421)

  | line       | gate                                              | step |
  |------------|---------------------------------------------------|------|
  | :265       | `range_check(tx_nonce, 32)`                       | nonce canonical |
  | :366-371   | per i: `asset_proof[i].verify(before_bal, idx, root)` | read balance |
  | :372       | per i: `new_bal = before_bal.sub(amount)`         | DEDUCT (no underflow) |
  | :373-374   | per i: `root = asset_proof[i].get_root(new_bal, idx)` | write back |
  | :376-380   | `transfer_tree_root = merkle(transfers)`          | build tx |
  | :389-394   | `sent_tx_proof.verify(empty_tx, nonce, root)`     | nonce slot was EMPTY (replay guard) |
  | :395-398   | `sent_tx_root = sent_tx_proof.get_root(tx, nonce)`| record tx at nonce |
  | :400-410   | build `new_private_state` (nonce+1, prev commit)  | IVC link |
  | :412       | `is_valid = is_equal(tx_nonce, prev.nonce)`       | flag (NOT asserted!) |
  | :421       | `register_public_inputs(...)`                     | expose PIs |
-/

namespace Zkp
namespace Circuits.SpendCircuit

open CField Builder Bytes Merkle U256

variable {F : Type} [CField F]

def ASSET_TREE_HEIGHT : Nat := 32
def SENT_TX_TREE_HEIGHT : Nat := 32

/-- One transfer's deduction witness. -/
structure TransferStep (F : Type) [CField F] where
  before : U256 F
  amount : U256 F
  newBal : U256 F
  tokenIndex : F
  sib : List (HashOut F)

/-- One read-deduct-write step along a shared Merkle path: reads
    `before` at `tokenIndex` under `rootIn`, deducts `amount` (no
    underflow), writes `newBal` giving `rootOut`. The shared `bits`
    guarantee only the `tokenIndex` leaf changes. -/
def DeductStep (rootIn rootOut : HashOut F) (s : TransferStep F) : Prop :=
  (∃ bits : List Bool, bits.length = ASSET_TREE_HEIGHT ∧
      s.tokenIndex = bitsValue bits ∧
      fold (u256Leaf s.before) bits s.sib = rootIn ∧
      fold (u256Leaf s.newBal) bits s.sib = rootOut)
  ∧ SubSpec s.before s.amount s.newBal

/-- The threaded chain of deductions over all transfers, starting at
    the sender's `asset_tree_root` and ending at the post-spend root. -/
def Deducts : HashOut F → List (TransferStep F) → HashOut F → Prop
  | rootIn, [], rootOut => rootIn = rootOut
  | rootIn, s :: rest, rootOut =>
      ∃ rootMid, DeductStep rootIn rootMid s ∧ Deducts rootMid rest rootOut

/-- **Per-transfer solvency.** Every deduction in an accepted spend had
    sufficient balance: `amount ≤ before`. Proved from the
    underflow-rejecting `SubSpec` at each step — a sender can never
    send more than they hold, on ANY of the (up to 64) transfers. -/
theorem deducts_solvent {rootIn rootOut : HashOut F} :
    ∀ {steps : List (TransferStep F)}, Deducts rootIn steps rootOut →
      ∀ s ∈ steps, uval s.amount ≤ uval s.before := by
  intro steps
  induction steps generalizing rootIn with
  | nil => intro _ s hs; cases hs
  | cons hd tl ih =>
      intro h s hs
      obtain ⟨rootMid, hstep, hrest⟩ := h
      rcases List.mem_cons.mp hs with rfl | htl
      · exact (sub_no_underflow hstep.2).1
      · exact ih hrest s htl

/-- The sent-tx replay guard: the slot at `nonce` was EMPTY before
    (`verify(empty_tx, nonce, prevRoot)`), and recording the tx there
    yields `newRoot`. Emptiness is what prevents reusing a nonce to
    replay a spend. -/
def SentTxRecord (prevRoot newRoot : HashOut F)
    (emptyLeaf txLeaf : HashOut F) (nonce : F) (sib : List (HashOut F)) : Prop :=
  ∃ bits : List Bool, bits.length = SENT_TX_TREE_HEIGHT ∧
    nonce = bitsValue bits ∧
    fold emptyLeaf bits sib = prevRoot ∧
    fold txLeaf bits sib = newRoot

/-- **Spend soundness (top level).** Bundles solvency of all transfers
    with the replay guard. `prevAssetRoot/finalAssetRoot` are the
    sender's asset roots before/after; `steps` the per-transfer
    deductions. -/
theorem spend_sound
    {prevAssetRoot finalAssetRoot : HashOut F} {steps : List (TransferStep F)}
    {prevSentRoot newSentRoot emptyLeaf txLeaf : HashOut F} {nonce : F}
    {sentSib : List (HashOut F)}
    (hded : Deducts prevAssetRoot steps finalAssetRoot)
    (hsent : SentTxRecord prevSentRoot newSentRoot emptyLeaf txLeaf nonce sentSib) :
    (∀ s ∈ steps, uval s.amount ≤ uval s.before) ∧
    (∃ bits, bits.length = SENT_TX_TREE_HEIGHT ∧ nonce = bitsValue bits ∧
       fold emptyLeaf bits sentSib = prevSentRoot) := by
  refine ⟨deducts_solvent hded, ?_⟩
  obtain ⟨bits, hlen, hnonce, hempty, _⟩ := hsent
  exact ⟨bits, hlen, hnonce, hempty⟩

/-!
  ## SECURITY OBSERVATIONS

  * **Solvency proved.** `deducts_solvent` is the machine-checked
    statement that no transfer in a spend can exceed the sender's
    balance — the `connect_u32(borrow, zero)` gate in `U256::sub` is
    load-bearing, mirrored from native's `assert borrow==0` and the
    `prev_balance < amount` reject.

  * **F-SPEND-1 — `is_valid` is computed but NOT asserted.**
    `spend_circuit.rs:412` sets `is_valid = is_equal(tx_nonce,
    prev.nonce)` and registers it as a PI, but the circuit never
    `assert`s it true. So a proof with `tx_nonce ≠ prev_nonce`
    (is_valid = false) is still VALID. Sequentiality is enforced only
    if a CONSUMER checks `is_valid`. `TxSettlement` (modeled) binds
    `spend_pis.tx` but does NOT read `is_valid`. Action: find who
    asserts `is_valid` (balance_processor / send_tx_circuit). If
    nobody does, a sender could spend with an arbitrary `tx_nonce`
    (note: the sent-tx empty-slot check still blocks reusing the SAME
    nonce twice, and private `nonce` increments by 1 regardless, so
    impact is limited to nonce-ordering, not double-spend — but the
    flag's purpose is defeated if unchecked). Tracked for Phase 2.

  * **Replay guard.** `SentTxRecord` requires the `nonce` slot to hold
    the empty leaf before recording the tx — preventing a second spend
    at the same nonce. Soundness of "empty ⇒ unused" rests on the
    empty-leaf being a reserved sentinel (verify when modeling
    sent_tx_tree).
-/

end Circuits.SpendCircuit
end Zkp
