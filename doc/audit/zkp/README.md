# intmax3-zkp — Lean formalization & soundness audit

A line-by-line Lean 4 model of the Intmax3 Plonky2 ZKP circuits,
built to either **prove soundness** of each circuit statement or to
**surface the gap** where soundness cannot be proved (a candidate
vulnerability).

> Scope: ZKP circuits only. **Excluded:** cryptographic primitive
> implementations (Poseidon, SPHINCS+, Regev, MLE/WHIR internals —
> modeled as uninterpreted functions) and all **channel** circuits
> (`src/circuits/channel/`, `validity/channel_reg_hash_chain/`,
> `block_hash_chain/update_channel_tree.rs`).

## Why Lean, and what "express every line" means

A Plonky2 circuit is a set of gate constraints over field wires; a
proof exists iff some wire assignment satisfies all of them. Bugs in
ZK circuits are almost never wrong arithmetic — they are **missing
constraints**: a relation the protocol *assumes* but the circuit
never *asserts*, letting a malicious prover pick a witness the
verifier still accepts.

So each circuit is modeled as a **predicate over an arbitrary
satisfying witness**:

```
Constraints : inputs → outputs → Prop        -- conjunction of every emitted gate
nativeSpec  : inputs → outputs               -- the intended (honest) semantics
theorem sound : Constraints i o → o = nativeSpec i
```

- A `builder.connect/assert_*` call becomes a conjunct of `Constraints`.
- A deterministic gate (`add`, `mul`, `select`, `constant`) becomes a
  Lean function (the prover has no freedom in its output).
- A *witnessed advice* wire (e.g. the inverse in `is_equal`, a range
  hint) becomes an existential/relation — never a function — so the
  model never over-constrains the prover and hides a real gap.

**If `sound` is provable, the circuit binds what it should. If it is
*not* provable, the unprovable obligation pinpoints the missing
constraint** — that is the audit signal. Each such gap is recorded as
an `F-*` finding in `tasks/todo.md` with an inline `SECURITY FINDING`
note at the Lean site.

The translation is faithful line-by-line: every `*.lean` circuit file
cites the exact `source.rs:line` ranges for each constraint it models.

## Trusted base (axioms)

The entire trusted algebraic base is `Zkp/Core/Field.lean`: a
commutative field that is an integral domain (`mul_eq_zero`). We do
**not** axiomatize the Goldilocks characteristic; any argument needing
`2^32 < p`, canonical-form uniqueness, or range bounds must make that
dependency explicit at its use site (`Builder.rangeCheck`,
`Bytes.IsByte`) so it cannot be smuggled in. Poseidon/Keccak are
uninterpreted functions; collision resistance, where the protocol
relies on it, is an explicit named hypothesis (`Bytes.PoseidonCR`).

## Layout

```
Zkp/Core/Field.lean      -- abstract field, boolean lemma, trusted axioms
Zkp/Core/Builder.lean    -- CircuitBuilder gate semantics (connect, assert_bool, select, range_check, is_equal)
Zkp/Core/Bytes.lean      -- Bytes32 / Address / U256 / HashOut, Poseidon (uninterpreted)
Zkp/Circuits/...         -- one file per Rust circuit file, mirroring src/circuits/ paths
tasks/todo.md            -- file inventory, phase plan, findings log (F-*)
tasks/lessons.md         -- modeling lessons / adjustments
```

## Build

```bash
cd doc/audit/zkp && lake build      # fast; no mathlib, self-contained
```

A successful build means every soundness/completeness theorem stated
so far is machine-checked. `sorry` is banned: a gap is recorded as an
*unprovable obligation we deliberately do not assert*, plus a finding
note — never as an admitted lemma.
```
