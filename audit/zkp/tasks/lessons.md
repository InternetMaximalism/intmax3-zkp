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
