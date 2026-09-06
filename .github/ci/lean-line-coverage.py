#!/usr/bin/env python3
"""Source-line inventory and checked declaration links; NOT a refinement proof.

All discovered source files are accounted for, including those still untranslated.
Green validation means an honest/internally consistent PARTIAL inventory, never
that each line is proved. --require-complete deliberately fails while source
refinement certificates and dependency proofs remain absent.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "lean_safety_guard", Path(__file__).with_name("lean-safety-guard.py"))
G = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(G)

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = "doc/audit/zkp/implementation-inventory.json"
PROJECT = "doc/audit/zkp"
SUBMODULE = "contracts/lib/polygon-plonky2"
CORE = {"contracts/src/": ".sol", "src/circuits/": ".rs"}
DEPENDENCIES = {
    "src/common/": ".rs", "src/ethereum_types/": ".rs", "src/utils/": ".rs",
    "src/regev/": ".rs", "src/falcon_sig/": ".rs", "src/poseidon_sig/": ".rs",
    "src/deprecated/": ".rs",
    SUBMODULE + "/mle/contracts/src/": ".sol",
    SUBMODULE + "/mle/src/": ".rs",
}
EXTRA = {"src/constants.rs", "src/wrapper_config.rs"}
STATUSES = {"translated", "non-executable", "test-only", "dependency-boundary", "untranslated"}


def physical_lines(text):
    return len(text.splitlines())


def category(path):
    if any(path.startswith(prefix) and path.endswith(ext) for prefix, ext in CORE.items()):
        return "core"
    if path in EXTRA or any(path.startswith(prefix) and path.endswith(ext)
                            for prefix, ext in DEPENDENCIES.items()):
        return "dependency"
    return None


def discover(root):
    # Include nonignored untracked sources too: a new circuit must not disappear
    # merely because it was not staged yet. Do not recursively traverse unrelated
    # worktrees or arbitrary filesystem roots.
    paths = G.command(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                      cwd=root).split("\0")
    nested = G.command(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard",
                        "--", "mle/contracts/src", "mle/src"], cwd=root / SUBMODULE).split("\0")
    paths.extend(SUBMODULE + "/" + path for path in nested)
    return {path: category(path) for path in set(paths) if category(path) is not None}


def load_json(root, path):
    return json.loads(G.checked_path(root, path).read_text(),
                      object_pairs_hook=G.unique_json_object)


def validate_partition(spans, line_count, module):
    G.require(isinstance(spans, list) and spans, "empty source-line partition")
    cursor = 1
    totals = {status: 0 for status in STATUSES}
    declarations, theorems = set(), set()
    for span in spans:
        G.exact_keys(span, {"start", "end", "status", "label", "declarations", "theorems", "note"},
                     "line span")
        start, end, status = span["start"], span["end"], span["status"]
        G.require(type(start) is int and type(end) is int and start == cursor
                  and start <= end <= line_count, "gap, overlap, reversed or out-of-range source span")
        G.require(isinstance(status, str) and status in STATUSES, "unknown line status")
        for key in ("label", "note"):
            G.require(isinstance(span[key], str) and span[key].strip(), "empty source-span explanation")
        for key, accumulator in (("declarations", declarations), ("theorems", theorems)):
            names = span[key]
            G.require(isinstance(names, list) and all(isinstance(n, str) for n in names)
                      and len(names) == len(set(names)), "invalid/duplicate declaration links")
            G.require(all(G.QUALIFIED.fullmatch(n) and n.startswith(module + ".") for n in names),
                      "declaration link escapes mapped module")
            accumulator.update(names)
        G.require(status != "translated" or span["declarations"],
                  "translated source span has no Lean declaration")
        G.require(status not in {"non-executable", "test-only", "untranslated"} or not span["theorems"],
                  "untranslated/non-production source counted as a proved property")
        totals[status] += end - start + 1
        cursor = end + 1
    G.require(cursor == line_count + 1, "source partition omits trailing lines")
    return totals, declarations, theorems


def validate(root, manifest):
    G.exact_keys(manifest, {"schema_version", "runtime_base_commit", "formalization_base_commit",
                           "scope_note", "files"}, "implementation inventory")
    G.require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1,
              "unsupported inventory schema")
    for key in ("runtime_base_commit", "formalization_base_commit"):
        value = manifest[key]
        G.require(isinstance(value, str) and G.HEX40.fullmatch(value), "invalid inventory base")
        G.command(["git", "merge-base", "--is-ancestor", value, "HEAD"], cwd=root)
    G.require(isinstance(manifest["scope_note"], str) and manifest["scope_note"].strip(),
              "missing scope boundary")
    expected = discover(root)
    files = manifest["files"]
    G.require(isinstance(files, list) and files, "empty implementation inventory")
    seen, maps = set(), set()
    totals = {status: 0 for status in STATUSES}
    per_category = {kind: {"files": 0, "lines": 0} for kind in ("core", "dependency")}
    probes = []
    # All model/map files must also be inside the reviewed-source manifest. This
    # connects line-map links to the separate full build/theorem-axiom guard.
    safety = load_json(root, G.MANIFEST)
    G.validate_manifest(root, safety)
    hashed = {f["path"]: f["role"] for f in safety["files"]}
    audited = {(c["project"], c["module"]): set(c["theorems"]) for c in safety["theorem_checks"]}
    G.require(INVENTORY in hashed, "source inventory absent from reviewed hashes")
    for entry in files:
        G.exact_keys(entry, {"path", "sha256", "lines", "category", "line_map"}, "source inventory entry")
        path = entry["path"]
        G.require(isinstance(path, str) and path not in seen and path in expected,
                  "duplicate or out-of-scope source")
        G.require(entry["category"] == expected[path], "source category mismatch")
        source = G.checked_path(root, path).read_bytes()
        digest = hashlib.sha256(source).hexdigest()
        lines = physical_lines(source.decode("utf8"))
        G.require(type(entry["lines"]) is int and entry["lines"] == lines and lines > 0,
                  "source line count changed")
        G.require(entry["sha256"] == digest, f"source changed, revisit line mapping: {path}")
        seen.add(path)
        per_category[entry["category"]]["files"] += 1
        per_category[entry["category"]]["lines"] += lines
        map_path = entry["line_map"]
        if map_path is None:
            totals["untranslated"] += lines
            continue
        G.require(isinstance(map_path, str) and map_path not in maps
                  and map_path.startswith(PROJECT + "/line-map/") and map_path.endswith(".json"),
                  "invalid/duplicate line-map file")
        maps.add(map_path)
        mapping = load_json(root, map_path)
        G.exact_keys(mapping, {"schema_version", "source", "source_sha256", "source_lines", "module",
                              "model", "refinement", "spans", "boundaries"}, "line map")
        G.require(type(mapping["schema_version"]) is int and mapping["schema_version"] == 1
                  and mapping["source"] == path and mapping["source_sha256"] == digest
                  and type(mapping["source_lines"]) is int and mapping["source_lines"] == lines,
                  "line map source identity mismatch")
        module, model = mapping["module"], mapping["model"]
        G.require(isinstance(module, str) and G.QUALIFIED.fullmatch(module)
                  and module.startswith("Zkp.Implementation."), "invalid implementation module")
        G.require(model == PROJECT + "/" + module.replace(".", "/") + ".lean",
                  "model path/module mismatch")
        G.checked_path(root, model)
        G.require(mapping["refinement"] == "not-proved",
                  "this schema has no source-refinement certificate format; do not claim completion")
        G.require(hashed.get(map_path) == "spec" and hashed.get(model) == "model"
                  and hashed.get(path) == "implementation", "mapped inputs missing from reviewed hashes")
        key = (PROJECT, module)
        G.require(key in audited, "mapped module is outside the theorem dependency audit")
        span_totals, declarations, theorems = validate_partition(mapping["spans"], lines, module)
        G.require(theorems <= audited[key], "source-linked theorem omitted from dependency audit")
        boundaries = mapping["boundaries"]
        G.require(isinstance(boundaries, list) and boundaries, "dependency boundary list is empty")
        boundary_names = set()
        for boundary in boundaries:
            G.exact_keys(boundary, {"name", "obligation", "discharged"}, "boundary")
            G.require(isinstance(boundary["name"], str) and boundary["name"].strip()
                      and boundary["name"] not in boundary_names, "duplicate/empty boundary")
            boundary_names.add(boundary["name"])
            G.require(isinstance(boundary["obligation"], str) and boundary["obligation"].strip()
                      and boundary["discharged"] is False,
                      "boundary evidence not supported; unresolved premises must stay explicit")
        for status in totals:
            totals[status] += span_totals[status]
        probes.append({"module": module, "declarations": declarations | theorems, "theorems": theorems})
    G.require(seen == set(expected), f"source inventory omitted files: {sorted(set(expected) - seen)}")
    actual_maps = set(G.command(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard",
                                 "--", PROJECT + "/line-map"], cwd=root).split("\0"))
    G.require(maps == {p for p in actual_maps if p.endswith(".json")},
              "orphaned/unlisted source line map")
    return totals, per_category, probes


def audit_links(root, probes):
    lake = shutil.which("lake")
    G.require(lake is not None, "lake missing from PATH")
    G.command([lake, "build"], cwd=root / PROJECT, capture=False)
    with tempfile.TemporaryDirectory(prefix="intmax-lean-lines-") as temp:
        for index, probe in enumerate(probes):
            lines = ["import Lean", "import " + probe["module"]]
            for name in sorted(probe["declarations"]):
                lines.append("#check " + name)
            for name in sorted(probe["theorems"]):
                lines.extend(["run_cmd do",
                              "  let info ← Lean.getConstInfo `" + name,
                              "  match info with",
                              "  | .thmInfo _ => pure ()",
                              '  | _ => throwError "line-map property is not a theorem"',
                              "#print axioms " + name])
            path = Path(temp) / f"LineLinks{index}.lean"
            path.write_text("\n".join(lines) + "\n")
            output = G.command([lake, "env", "lean", str(path)], cwd=root / PROJECT)
            G.require("sorryAx" not in output, "admitted line-map dependency")
            for name in probe["theorems"]:
                G.parse_axioms(output, name)


def main():
    G.require(sys.argv[1:] in ([], ["--require-complete"]), "unsupported coverage option")
    inventory = load_json(ROOT, INVENTORY)
    totals, categories, probes = validate(ROOT, inventory)
    audit_links(ROOT, probes)
    G.require(validate(ROOT, inventory)[:2] == (totals, categories), "inventory changed during build")
    print("[lean-lines] checked source inventory: " + json.dumps(categories, sort_keys=True))
    print("[lean-lines] physical-line classifications: " + json.dumps(totals, sort_keys=True))
    print(f"[lean-lines] {len(probes)} source maps have compiler-checked declaration links")
    print("[lean-lines] INCOMPLETE: untranslated sources, dependency obligations and source/EVM refinement remain")
    if sys.argv[1:] == ["--require-complete"]:
        raise G.GuardFailure("full implementation safety is NOT certified by this partial translation")
    print("[lean-lines] PASS means inventory/link consistency only, NOT all-line or whole-system proof")


if __name__ == "__main__":
    try:
        main()
    except (G.GuardFailure, OSError, ValueError, TypeError, KeyError) as error:
        print(f"[lean-lines] FAIL: {error}", file=sys.stderr)
        sys.exit(1)
