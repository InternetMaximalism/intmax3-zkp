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
