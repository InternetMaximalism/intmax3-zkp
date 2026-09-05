# intmax3-zkp — Lean formalization & soundness audit

> **Current alignment, 2026-09-05:** [current scope and assumptions](../lean-current-safety.md)
> target parent `c533e710` / submodule `b569e0d7`. The new independent
> `Zkp.Contracts.CurrentVerification` and architecture `ChannelSafetyCurrent` modules cover
> selected current security-critical transitions. The historical corpus described below has
> not been wholesale revalidated. In particular, removed burn claims, the old zero-degree
> verification bypass, and aggregate Manager payouts are not current code paths.

> ## ⚠ STALENESS / TARGET-COMMIT BANNER (added 2026-08-26)
>
> A Lean model verifies THE CODE IT WAS WRITTEN AGAINST, not the working
> tree. This corpus was audited against the codebase up to commit
> `2c358ae` (2026-08-20). Production has moved since — notably `fd467ea`
> (2026-08-24, sig-cluster: member cap 16 → 8, IMCM close-commitment
> re-layout) and detail2 §Q (dynamic member-set updates). Divergences
> found by the 2026-08-26 review are catalogued in
> `doc/audit/audit25-08-2026.md` Part 4.3; the load-bearing ones
> (constants, the §Q-falsified `member_set_immutable`, the contract line
> map) were re-synced on 2026-08-26 and are marked in-file. Sections not
> marked re-synced describe the `2c358ae` code. `lake build` green means
> the PROOFS are consistent — it does not mean the MODEL matches today's
> code; check this banner's date against `git log` before trusting a
> line cite. Both Lean corpora now build in CI on every push.


A line-by-line Lean 4 model of the Intmax3 Plonky2 ZKP circuits,
built to either **prove soundness** of each circuit statement or to
**surface the gap** where soundness cannot be proved (a candidate
vulnerability).

> Scope: ZKP circuits + L1 contracts. **Excluded:** cryptographic
> primitive implementations (Poseidon, Falcon, Regev, MLE/WHIR
> internals — modeled as uninterpreted functions) and the channel-scope
> circuits under `src/circuits/channel/`. NOTE (2026-08-26): the
> exclusion list previously printed here was stale —
> `validity/channel_reg_hash_chain/channel_reg_step.rs` and
> `block_hash_chain/update_channel_tree.rs` ARE modeled
> (`Circuits.ChannelRegStep`, `Circuits.UpdateUser`).

## Why Lean, and what "express every line" means

A Plonky2 circuit defines a set of satisfying assignments over field wires.
Connecting cryptographic verifier acceptance to such an assignment requires a
separate proof-system soundness argument; this corpus does not establish it. Bugs in
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

**If `sound` is provable, the modeled constraints imply the modeled specification**,
conditional on the explicit hypotheses. Applying that result to Rust requires a faithful
translation. A failed proof attempt can indicate a missing constraint, an incorrect model,
or an incomplete proof; it is not itself proof of a vulnerability. Each investigated gap is recorded as
an `F-*` finding in `tasks/todo.md` with an inline `SECURITY FINDING`
note at the Lean site.

The historical translation was manually reviewed with `source.rs:line` citations.
Those citations are not an automatically verified refinement relation and may be stale.
For the new bounded scope, source hashes and named theorem/assumption checks now make drift explicit.

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
Zkp/Core/Exponentiation.lean -- ExponentiationGate (id 8) ladder + the on-chain Solidity evaluator port
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
