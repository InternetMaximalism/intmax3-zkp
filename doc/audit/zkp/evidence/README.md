# Mechanical faithfulness evidence (Layer M)

`faithfulness-<program>.tsv` is generated, `faithfulness-<program>.ops` is the checked-in
expectation the generator diffs against. Both are produced by

```
export PATH=$HOME/.cargo/bin:$PATH
cargo test --release --locked --lib -- --test-threads=1 faithfulness
```

(the lib suite must run single-threaded; at any parallelism it is OOM-killed and the SIGKILL
reads as a test failure). To re-bless the `.ops` files after an intentional change, set
`INTMAX_FAITHFULNESS_BLESS=1`.

## What the tables claim

Each Lean per-primitive model under `doc/audit/zkp/Zkp/Implementation/` transcribes one plonky2
builder call of a circuit constructor into a `BuildOp`/`LeafOp`/`LevelOp`/`GadgetOp` and gives it
a local proposition (`holds`). A row of the table is one such op (indexed families are collapsed
into one row and named `op[a..b)`), with:

| column | meaning |
| --- | --- |
| `op` | the Lean constructor, as spelled in the model |
| `source` | the Rust line the Lean docstring cites |
| `kind` | which part of `holds` this row checks |
| `verdict` | `ok` / `MISMATCH` / `not-static` / `trivial` / `mutation` / `not-injectable` |
| `detail` | the concrete claim, in words |

An op may occupy several rows when its `holds` has both a structural and a non-structural half
(e.g. `recomputeH1AndConnect` = a gadget relation *and* a `connect`).

### `kind`

* `connect` — a wire equality (`builder.connect`, `connect_array`, `Bytes32Target::connect`).
* `constant` — a wire pinned to a cached constant (`assert_zero`, `assert_one`,
  `builder.constant(c)`).
* `range` — a `range_check(t, n)` of a specific width, or the *absence* of one where the Lean op
  deliberately constrains nothing (`rawSlotRoot4`, `allocatePrivateUnchecked`).
* `public-inputs` — which wires are registered, and in what order.
* `aliasing` — the Lean op states that two names denote the SAME target (checked by target
  identity, not by the partition).
* `preimage` — the layout of a hash gadget's argument vector.
* `width` — a wire-vector length the Lean op fixes.
* `config` / `no-gate` — the config choice and the constraint-free calls.
* `arith` / `gadget` — the non-structural halves.

### `verdict`

* `ok` — the check ran against the built circuit and passed.
* `MISMATCH` — the Lean `holds` claim does NOT hold in the built circuit. The generating test
  fails on any such row; a table on disk should never contain one.
* `not-static` — the claim is arithmetic or gadget semantics, invisible to the copy-constraint
  partition. It stays in the per-primitive premise.
* `trivial` — the Lean `holds` is `True` (config choice, struct literal, profiling read).
* `mutation` — covered by a proving test that violates exactly this claim; the `detail` names it.
* `not-injectable` — the violation cannot be expressed through the circuit's public witness API.

### `CloseAssetBacking`

`faithfulness-CloseAssetBacking.tsv` used to carry a caveat: the Lean module had a `BuildOp`
transcript but no per-op `holds`, so the table was diffed against what each op's *name and
docstring* asserted, plus whichever `CircuitConstraints` fields happened to be copy constraints.
**That caveat is gone.** `doc/audit/zkp/Zkp/Implementation/CloseAssetBacking.lean` now defines
`BuildOp.holds` for all 45 constructors (468 program entries) over an `Assignment` of every wire
the constructor allocates, and `program_satisfied_implies_constraints` derives every
`CircuitConstraints` field from `ProgramSatisfied constructorProgram` alone. The table is now
diffed against those actual `holds` cases: there is exactly **one row per `BuildOp` constructor**
(46 rows, counting `registerPublicInputs` and `buildCircuit`), each row's `detail` opens with the
`holds` proposition it is diffing, and the verdict says whether the built circuit was checked
against it (`ok`), whether the proposition is arithmetic/gadget semantics the partition cannot see
(`not-static`), or whether `holds` is literally `True` (`trivial`).

Four rows moved from `not-static` to `ok` in that re-diff, because the `holds` case is a plain
`connect` to the zero constant rather than the arithmetic that produced the wire:
`connectNoRiseZero`, `connectInactiveRegistryZero`, `connectInactiveAmountZero` and
`connectDuplicateZero` (9 + 10 + 80 + 45 = 144 wires). The multiply/`is_equal`/`and`/`not` ops that
*feed* them stay `not-static`. Rows previously merged (`allocateCount / rangeCount32`,
`constantZero / constantOne`, the three digest-preimage ops) were split so that each constructor
is diffed on its own, and several checks were widened to the full `holds` conjunction — notably
`allocateExtendedChecked` (all eight conjuncts of `ExtendedPublicState.Checked`, including
`blockNumber < 2^63` and `depositCount < 2^63`), `connectInnerPublicState` (all 15 inner wires),
`decodeBalanceTargetPis` (all 29 re-sliced statement wires) and `constantZero` (the second
conjunct, `activitySumWire 0 = zeroWire`). A constructor whose `holds` is `True` but whose
docstring still makes a checkable structural claim carries that claim as its executed check and
says so in the `detail`, so a docstring that stops describing the circuit surfaces as a `MISMATCH`
too. No `MISMATCH` row was produced: 27 `ok`, 16 `not-static`, 3 `trivial`.

## How the static check works

After `CircuitBuilder::build`, `CircuitData.prover_only.representative_map`
(`plonky2/src/plonk/circuit_data.rs:375`) is the path-compressed union-find over every wire and
virtual target, indexed by `Target::index(num_wires, degree)` (`plonky2/src/iop/target.rs:55`).
Two targets are wired equal by `connect` iff their representatives coincide. Constants are found
by scanning the `Gate::extra_constant_wires` slots (`ConstantGate`, `RandomAccessGate`) against
`prover_only.constant_evals`; a gate forces such a wire to its constant, so a target sharing a
representative with one is pinned to that value. Range-check widths are recovered from the
`BaseSumGate<2>` row that `split_le` adds: the sum wire is connected to the checked target and
the surplus limbs above the requested width are asserted zero. `crate::faithfulness` (test-only)
implements this; `faithfulness_repview_self_check` pins all three primitives on a purpose-built
toy circuit.

## Caveat on the `source` column

The `source` line numbers are those of the UNMODIFIED runtime files — the same ones the Lean
docstrings cite. Running the generator requires `#[cfg(test)]`-only probe structs and capture
statements inside the constructors (they expose internal wires the returned `*Target` structs do
not keep). Those are compiled out of every non-test build, so the production constraint system is
byte-identical; the diff that installs them contains no deletions at all. But while they are
applied, the working-tree line numbers are shifted downward (by +27 to +41 entering each
constructor, +45 to +72 leaving it).

The authoritative mapping is NOT this table: it is `doc/audit/zkp/line-map/*.json`, which has been
re-based onto the probed tree by `doc/audit/zkp/agent-tools/shift-linemap.py`. Every inserted line
is carried there as a span with `"status": "test-only"` — 10 spans in `close-circuit.json`, 10 in
`withdrawal-claim-circuit.json`, 8 each in `post-close-claim-circuit.json`, `close-asset-backing.json`
and `falcon-agg.json`, 6 in `falcon-gadget.json` — and every map's `source_sha256`/`source_lines`
match the file on disk. Read a `source` cell of a table through the line map, not by adding an
offset by hand.

`shift-linemap.py` aborts unless the change is INSERT-ONLY (no line deleted or modified). That it
ran to completion on all six files is an independent mechanical confirmation of the property this
layer depends on: the probes add lines and change none, so the runtime constraint system outside
`#[cfg(test)]` is byte-identical.

## Measured run cost (2026-09-11, audit machine)

`cargo test --release --locked --lib -- --test-threads=1 faithfulness`: 18 tests, 209 s wall (221.9 s on the second run after the CloseAssetBacking re-diff), peak RSS 26.6 GB. Touched-module regressions re-run alongside: 76 tests / 1,237 s / 33.5 GB and `close_circuit::tests` 17 tests / 196 s / 8.8 GB. The lib suite is OOM-killed at any parallelism; a SIGKILL looks like a test failure.
