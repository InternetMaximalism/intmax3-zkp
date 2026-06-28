# Lean modeling lessons (audit/zkp)

## Lean 4.10 / self-contained core gotchas
- `Zero`/`One` are **mathlib** classes, not Lean core. Without mathlib,
  use `OfNat F 0` / `OfNat F 1` instances instead.
- `rw` matches surface syntax: axioms stated on the raw class function
  `add`/`mul` won't `rw` against `+`/`*` goals. Provide notation-form
  restatements (`addC`, `mulA`, `distribL`, …) that hold by `rfl`.
- `opaque f : T → U` requires `Inhabited U`. Add `instance : Inhabited F
  := ⟨zero⟩` in the `CField` namespace so opaque field-valued decls work.
- `omega` does NOT unfold `def`s. To reason about `SubSpec a b r`
  (`:= uval r + uval b = uval a`), first `have h' : ... := h` to expose
  the ℕ equation, then `omega`.
- **Structure fields cannot share a type annotation**: `a b : T` is a
  parse error in `structure ... where` ("failed to infer binder type").
  One field per line.

## Modeling conventions that paid off
- Deterministic gates = Lean functions (prover has no freedom);
  assertions = `Prop`; witnessed advice = existential/relation. Keeps the
  model from over-constraining the prover and hiding real gaps.
- A finding = an *unprovable strengthening* of the soundness theorem
  (e.g. F-RECIP-1: `recipient = recipientFromAddress out` is not provable
  from the constraints). Don't `sorry` it — state the weaker provable
  theorem and write the gap as a `SECURITY FINDING` note + todo entry.
- Conditional gates (`conditional_verify`, `select`, `conditional_assert_eq`)
  modeled as `cond = 1 → ...` / `SelectSpec`. The recurring proof pattern
  for "prover can't skip": case-split on the boolean, use
  `notGate_eq_one_iff` / `andGate_eq_one_iff`.

## Cross-cutting safe patterns observed in the Rust
- U256 `add`/`sub` both end with `connect_u32(carry/borrow, zero)` ⇒
  overflow AND underflow are rejected in-circuit (solvency + no inflation).
- Tree index widths are deliberately matched to range-check widths
  (U63=DEPOSIT_TREE_HEIGHT=63, TOKEN_INDEX_BITS=ASSET_TREE_HEIGHT=32,
  CHANNEL_ID_BITS=TX_TREE_HEIGHT=CHANNEL_TREE_HEIGHT=32) ⇒ no index aliasing,
  provided `is_checked=true` (all in-scope callers pass it).
- `is_valid`-style flags are consumed downstream as no-op selectors, not
  asserted at the producing circuit — check the CONSUMER before flagging.

## Contract modeling lessons
- `omega` failed to ingest hypotheses typed `U256` (an `abbrev` for `Nat`)
  with "no usable constraints found" — it did not unfold the abbrev in the
  hypothesis/goal atoms. Workaround: discharge with explicit `Nat` lemmas
  (`Nat.sub_add_cancel`, `Nat.add_le_add_left`, `Nat.add_assoc/comm`) or a
  `calc`. (Alternatively use `Nat` directly in storage structs.)
- Model Solidity-0.8 checked arithmetic as `Option` (none = revert):
  `checkedSub`/`checkedAdd`. The underflow-revert on `totalEscrowed -= amount`
  IS the global solvency invariant — never model it with saturating ℕ sub.
- External functions = `State → ... → Option State` (none = revert). `require`
  becomes guard `if ¬cond then none`. Decompose a successful call with a
  `*_some` lemma (guards-false + the post-state) and reuse it across proofs.
- Crypto verifiers (Groth16/KZG/MLE) are uninterpreted `... → Bool` oracles,
  exactly как Poseidon/keccak in the circuit model — contract reasoning is
  about accounting / access-control / replay / CEI, not the primitives.
