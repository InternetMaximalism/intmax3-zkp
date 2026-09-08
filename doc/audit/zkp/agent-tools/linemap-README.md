# Line-map authoring rules (intmax3 Lean audit)

Checkout root: <root> — the git worktree this file lives in; every path below is relative to it.
The operator substitutes the real absolute path when briefing an agent.
Lean project:  <root>/doc/audit/zkp   (toolchain: PATH=/Users/andropov/.elan/bin:$PATH ; do NOT run a bare `lake build` of everything; `lake build Zkp.Implementation.<YourModule>` and `lake env lean` are fine)
Validator:     python3 <root>/doc/audit/zkp/agent-tools/validate-linemap.py <map.json>
Examples:      <root>/doc/audit/zkp/line-map/h1-gadget.json, update-private-state.json (has test-only spans), close-circuit.json, switch-board.json

## Schema (exact keys)
{
  "schema_version": 1,
  "source": "<repo-relative source path>",
  "source_sha256": "<sha256 of file bytes>",
  "source_lines": <physical line count = len(text.splitlines())>,
  "module": "Zkp.Implementation.<Name>",
  "model": "doc/audit/zkp/Zkp/Implementation/<Name>.lean",
  "refinement": "not-proved",
  "spans": [ {"start","end","status","label","declarations","theorems","note"}, ... ],
  "boundaries": [ {"name","obligation","discharged": false}, ... ]   (non-empty)
}

## Span rules (enforced by CI)
- Spans are contiguous, start at 1, end at source_lines, no gaps/overlaps, start<=end.
- status ∈ translated | non-executable | test-only | dependency-boundary | untranslated.
- "translated" spans MUST list ≥1 declaration of the mapped module that models those exact lines.
- "non-executable", "test-only", "untranslated" spans MUST have theorems: [] (declarations may be [] too).
- "dependency-boundary" spans: code whose semantics comes from an imported crate/gadget/hash/compiler that the
  model treats as an opaque callback or premise (e.g. Poseidon, Merkle gadget, plonky2 builder API, `use` lines).
  May list declarations (the structure/premise that models the interface) and theorems ONLY if a theorem is
  genuinely about that interface premise.
- All declaration/theorem names fully qualified and inside the mapped module namespace (Zkp.Implementation.<Name>.x).
- Every name must exist in the built module (validator runs #check). Theorem links must be `theorem` decls.
- label/note non-empty strings. Keep notes honest: "Handwritten local semantics; no source/compiler refinement" style.

## Honesty rules (the whole point)
- Mark a span "translated" ONLY if the Lean module actually has a definition/structure that models what those
  source lines do. If the Lean model merely mentions or abstracts it as an opaque function, it is dependency-boundary.
  If nothing in the module corresponds, it is "untranslated" (fine and expected for parts of large files).
- Comments (`//`, `///`, `//!`), blank lines, `#[derive]`, `#[cfg]` attributes, closing braces, `impl` headers
  with no executable content → non-executable (prefer separate spans for comment blocks ≥ 3 lines).
- `#[cfg(test)]` modules and test helpers → test-only.
- Do not link a theorem to a span unless the theorem's statement is about the behavior of those lines.
- Do not invent safety claims; a theorem about a parser does not cover the verifier that calls it.
- Prefer coarse, accurate spans over many tiny ones, but never merge translated code with untranslated code.

## Boundaries
List each undischarged premise class the model relies on for this file (hash injectivity, gadget lowering,
native/target refinement, signature validity, finality, etc.), with an "obligation" sentence. discharged is always false.

## Workflow
1. Read the source completely with line numbers (`nl -ba`).
2. Read the Lean module completely; list its declarations (`grep -n '^def\|^structure\|^inductive\|^theorem\|^abbrev\|^instance' file`).
3. Build the map; compute sha via `shasum -a 256 <source>`, lines via python `len(text.splitlines())`.
4. Run the validator until it prints "PROBE OK". Do not edit the Lean module or the source to make a map pass.
5. Write the map to <root>/doc/audit/zkp/line-map/<kebab-name>.json (2-space indented JSON, trailing newline).
6. Report: totals per status, number of decls/theorems linked, and anything in the source that the Lean model does
   NOT cover that looks security-relevant.
