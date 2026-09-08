# Authoring a `Zkp.Implementation.<Name>` module (intmax3 Lean audit)

Checkout root: <root> — the git worktree this file lives in; every path below is relative to it.
The operator substitutes the real absolute path when briefing an agent.
Lean project:  <root>/doc/audit/zkp — Lean 4.10.0, NO Mathlib. Always `PATH=/Users/andropov/.elan/bin:$PATH`.
Never touch git (the operator commits). Never edit files other than the ones assigned to you. Never edit Rust/Solidity/JS sources.
Work fast and save early: write the module file to disk as soon as its skeleton exists and keep it on disk between
edits (the operator commits WIP checkpoints from disk; work only in memory is lost if the session dies).

## What a module is
A handwritten SEMANTIC MODEL of one source file (occasionally a few closely related files), plus kernel-checked
theorems about that model. It is NOT a refinement proof of the Rust/plonky2/Solidity code, and the header docstring
must say so. Study these examples before writing anything:
- small/clean: Zkp/Implementation/UpdatePrivateState.lean, UpdatePublicState.lean, PrivateState.lean
- circuit with native admission vs arbitrary witness split: Zkp/Implementation/CloseCircuit.lean, WithdrawalClaimCircuit.lean
- public-input codec: Zkp/Implementation/BalancePublicInputs.lean, ClosePublicInputs.lean
- big verifier with Except do-blocks: Zkp/Implementation/ChannelStateUpdate.lean (see proof pattern below)

## Hard rules (CI-enforced)
- `namespace Zkp.Implementation.<Name>` matching the file path `Zkp/Implementation/<Name>.lean`.
- Imports: only `Std` (or `Init`/`Lean`) and other *registered current* modules, i.e. anything listed in
  `CURRENT` of <root>/.github/ci/lean-safety-guard.py (all `Zkp.Implementation.*` there), plus modules named in
  your task as already built. Never import `Zkp.Circuits.*`, `Zkp.Core.*`, `Zkp.Contracts.*` historical models.
- No `sorry`, `admit`, `axiom`, `native_decide` anywhere (avoid the words even in comments; name things
  e.g. `admitSettlement` → prefer `acceptSettlement`). Only `propext`, `Classical.choice`, `Quot.sound` may appear transitively.
- Every theorem is declared as `theorem <plain_ascii_snake_case_name>` at column 0 (no `private`/`protected`,
  no unicode names). Any other theorem-declaration syntax breaks the inventory.
- Do NOT state as theorems things the source does not guarantee: no proof soundness, no hash injectivity (hash is an
  opaque callback / explicit premise on the concrete compared pair), no signature validity, no freshness from
  `root != oldRoot`, no finality, no "acceptance ⇒ safe". Keep those as explicit `structure`/`Prop` premises or
  opaque callbacks and NAME them in the header and in the map's `boundaries`.
- Separate NATIVE admission (the Rust witness builder / `new` that returns `Result`) from ARBITRARY satisfying
  witnesses (`CircuitGates`-style Prop with the local gate equations). Do not let a theorem about the native path
  silently cover adversarial witnesses.
- Prefer executable `def`s returning `Except`/`Option` mirroring the source control flow (order of checks, error
  precedence, panics vs errors), then theorems that *derive* facts from them (`= .ok _ → ...`).
- Add at least one non-vacuous positive example theorem (a concrete normal trace / satisfying witness).
- Pin constants from the source as literals (`def foo : Nat := 32`) and state `theorem foo_pinned`.

## Proof pitfalls (learned the hard way)
- Over big Except do-blocks NEVER use `repeat' (apply every_bind; intro)`; a failing final `apply` makes the
  unifier unfold `List.range 1024` and the file runs 20+ min at 19 GB. Instead:
  `intro p accepted; simp only [verifyX, bind_ok_iff, exists_unit, pure_ok_iff] at accepted` then peel with
  `repeat' (first | obtain ⟨_, accepted⟩ := (accepted : _ ∧ _) | obtain ⟨_, accepted⟩ := (accepted : ∃ _, _))`.
  `simp only` inlines do-notation join points, so an `if`/`match` mid-block carries the rest of the block in its
  branches: `split at accepted` there; kill `throw` branches with `throw_ok_iff_false, false_and, exists_false`.
  Copy the helper lemmas (`bind_ok_iff`, `unit_bind_ok_iff`, `exists_unit`, `check_ok_iff`, `pure_ok_iff`,
  `throw_ok_iff_false`) from ChannelStateUpdate.lean into your own namespace if you need them.
- If a proof must inspect a big constant list (e.g. `List.range slotCount`), put `attribute [local irreducible] slotCount`
  or reason by lemma, never by `decide`/`rfl` on the expanded list.
- `omega` treats `max`/`Int.toNat`/`%` of non-literals as atoms: case split and feed `Int.toNat_of_nonneg`.
- `(x::xs)[0]? = some x` is not `rfl` in 4.10: use `by simp`. `List.getElem?_cons_succ` for the successor case.
- Compile with `cd <root>/doc/audit/zkp && python3 <root>/doc/audit/zkp/agent-tools/tmo.py 300 lake env lean Zkp/Implementation/<Name>.lean`
  (no olean written; fast iteration; exit 124 = timeout → bisect with a truncated copy plus `end Zkp.Implementation.<Name>`;
  the culprit is the first declaration after the last fast prefix).
- KERNEL-TIMEOUT POISONING (costly, learned the hard way): a `simp` that unfolds a chain of small `Nat`
  defs through a derived-`DecidableEq` structure literal can elaborate in milliseconds yet produce a proof
  term the KERNEL needs minutes and gigabytes to check. Once one declaration reports
  `(kernel) deterministic timeout`, every later declaration in the file reports it too — spuriously — so
  prefix bisection points at the wrong place. Diagnose with `set_option profiler true` and compare
  `type checking` vs `elaboration` time; fix by replacing the `simp` with a structured proof
  (`if_neg`/`rcases`/`omega`), using `decide` only on closed small arithmetic.
- Finish with ONE `lake build Zkp.Implementation.<Name>` (other agents build other modules concurrently; fine).

## Line map (mandatory)
After the module builds, write doc/audit/zkp/line-map/<kebab-name>.json following <root>/doc/audit/zkp/agent-tools/linemap-README.md
and validate with `python3 <root>/doc/audit/zkp/agent-tools/validate-linemap.py <map>` until "PROBE OK". One map per source file;
a module modeling several files needs one map per file, all pointing at the same module.

## Report back (concise)
Module path, line count, theorem count, build result, validator totals per status per map, the list of named
boundaries, and 3–8 bullet "security-relevant source behaviour the model covers / does NOT cover".
Do not register the module anywhere (Zkp.lean, guard CURRENT, manifest, inventory) — the operator does that.
