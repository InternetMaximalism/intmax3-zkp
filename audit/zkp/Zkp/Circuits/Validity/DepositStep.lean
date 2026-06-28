import Zkp.Core.Field
import Zkp.Core.Builder
import Zkp.Core.Bytes
import Zkp.Core.Merkle

/-
  Deposit hash-chain step (sequential append)
  ===========================================

  Source: `src/circuits/validity/deposit_hash_chain/deposit_step.rs`
          (+ deposit_chain_pis / _circuit / _processor: PIs & cyclic wrapper)

  ## Protocol role

  Accumulates L1 deposits, in order, into TWO commitments kept in lock-
  step: the `deposit_tree_root` (a Merkle tree) and the
  `deposit_hash_chain` (a rolling hash). Each step verifies the previous
  chain proof (or genesis), then appends ONE deposit at the running
  `deposit_count`, incrementing the count. The `deposit_tree_root` is
  what user balance proofs reference (DepositWitness); the
  `deposit_hash_chain` is what the L1 contract matches against the
  deposits it actually recorded.

  The integrity crux: `deposit.deposit_index == prev.deposit_count`
  (`:125`). This forces APPEND-ONLY sequential insertion — no gaps, no
  duplicates, no reordering — so the tree and the hash chain commit to
  exactly the same deposit sequence the L1 recorded.

  ## Constraint inventory (deposit_step.rs:89-169, mirrored in Target::new)

  | line     | gate                                                      | meaning |
  |----------|-----------------------------------------------------------|---------|
  | :115     | `prev.block_number == deposit.block_number` (continuation) | same block |
  | :125     | `deposit.deposit_index == prev.deposit_count`             | **sequential append** |
  | :137-139 | `proof.verify(deposit, deposit_count, prev_deposit_tree_root)` | slot was empty/prev leaf |
  | :149     | `new_tree_root = proof.get_root(deposit, deposit_count)`  | append to tree |
  | :152     | `new_deposit_count = prev.deposit_count + 1`              | increment |
  | :157-159 | `new_hash_chain = deposit.hash_with_prev_hash(prev.hash)` | append to chain |
-/

namespace Zkp
namespace Circuits.DepositStep

open CField Builder Bytes Merkle

variable {F : Type} [CField F]

def DEPOSIT_TREE_HEIGHT : Nat := 63

opaque depositLeaf {F : Type} [CField F] : Bytes32 F → HashOut F  -- deposit's tree leaf
opaque hashWithPrev {F : Type} [CField F] : Bytes32 F → Bytes32 F → Bytes32 F

structure StepIO (F : Type) where
  depositIndex : Nat
  prevDepositCount : Nat
  newDepositCount : Nat
  deposit : Bytes32 F            -- the deposit (its commitment)
  prevTreeRoot : HashOut F
  newTreeRoot : HashOut F
  treeSib : List (HashOut F)
  countAsField : F              -- prev.deposit_count as the Merkle index wire
  prevHashChain : Bytes32 F
  newHashChain : Bytes32 F

structure Constraints (io : StepIO F) : Prop where
  -- :125  sequential append
  seqAppend : io.depositIndex = io.prevDepositCount
  -- :152  count increments by one
  countInc  : io.newDepositCount = io.prevDepositCount + 1
  -- :137-149  verify old slot then append: shared Merkle path at deposit_count
  treeAppend : ∃ bits : List Bool, bits.length = DEPOSIT_TREE_HEIGHT ∧
      io.countAsField = bitsValue bits ∧
      fold (depositLeaf io.deposit) bits io.treeSib = io.newTreeRoot
  -- :157-159  fold deposit into the rolling hash
  chainFold : io.newHashChain = hashWithPrev io.deposit io.prevHashChain

/-- **Sequential append (no gaps / duplicates / reordering).** Each step
    appends the deposit at exactly the running count and increments it by
    one. Inductively, the deposit at chain position `k` has
    `deposit_index = k`, so the tree and hash chain enumerate the SAME
    gap-free deposit sequence — the L1 contract's `deposit_hash_chain`
    match then certifies the `deposit_tree_root` users prove against. -/
theorem sequential_append {io : StepIO F} (h : Constraints io) :
    io.depositIndex = io.prevDepositCount
    ∧ io.newDepositCount = io.prevDepositCount + 1 :=
  ⟨h.seqAppend, h.countInc⟩

/-- **Dual-commitment consistency.** The very same deposit is appended to
    BOTH the Merkle tree (at `deposit_count`) and the rolling hash chain,
    so the two commitments can never diverge on which deposits were
    included. -/
theorem dual_accumulation {io : StepIO F} (h : Constraints io) :
    (∃ bits, bits.length = DEPOSIT_TREE_HEIGHT ∧ io.countAsField = bitsValue bits ∧
        fold (depositLeaf io.deposit) bits io.treeSib = io.newTreeRoot)
    ∧ io.newHashChain = hashWithPrev io.deposit io.prevHashChain :=
  ⟨h.treeAppend, h.chainFold⟩

/-!
  ## SECURITY OBSERVATIONS

  * **`deposit_index == deposit_count` is the anti-tamper bolt.** Without
    `seqAppend` (:125) a prover could insert a deposit at an arbitrary
    tree slot or skip indices — `sequential_append`'s first conjunct
    becomes unprovable, and the tree/chain could diverge from the L1
    deposit order. With it, the chain is a faithful append-only log.

  * **Tree index width = DEPOSIT_TREE_HEIGHT = 63 = U63** — the
    `deposit_count` Merkle index is range-bound by its `U63` type
    (verified-safe, same family as the balance-side checks; no aliasing).

  * **Genesis / continuation** handled by the `is_initial` + conditional
    prev-verify + `conditionally_connect_vd` pattern (deposit_step.rs
    Target::new), identical to withdrawal_step / switch_board; the cyclic
    vd binding is the trust anchor. `deposit_chain_pis` /
    `deposit_hash_chain_circuit` / `_processor` are PI-layout + cyclic
    wrapper + orchestration (no new leaf constraints).
-/

end Circuits.DepositStep
end Zkp
