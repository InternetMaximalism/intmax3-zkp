#!/usr/bin/env python3
"""Fail-closed Lean coverage, reviewed-source hash, and theorem-axiom guard.

This checks conditional mathematical models and their reviewed source snapshot.
It does NOT prove that the hand-written models refine Rust/Solidity/EVM semantics,
nor discharge cryptographic, field, hash, or environment hypotheses. Historical
models retain their documented trusted base; only the two current modules get the
strict transitive kernel-axiom allowlist below. No manifest field can relax it.
"""

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "doc/audit/lean-current-source-manifest.json"
CURRENT = {
    "doc/architecture-audit": "ChannelSafetyCurrent",
    "doc/audit/zkp": "Zkp.Contracts.CurrentVerification",
}
ARCH_ROOTS = frozenset({
    "ChannelSafety", "ChannelSafety2", "ChannelSafety21", "ChannelSafetyMT",
    "ChannelSafetyQ", "ChannelSafetyClose", "ChannelSafetyPW", "ChannelSafetyIC",
    "ChannelSafetyCurrent",
})
KERNEL_AXIOMS = frozenset({"propext", "Classical.choice", "Quot.sound"})
IDENT = r"[A-Za-z_][A-Za-z0-9_']*"
QUALIFIED = re.compile(rf"{IDENT}(?:\.{IDENT})*\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
REQUIRED_TOOLING = {
    ".github/workflows/ci.yml",
    ".github/ci/lean-safety-guard.sh",
    ".github/ci/lean-safety-guard.py",
    ".github/ci/test-lean-safety-guard.py",
    "doc/architecture-audit/lakefile.lean",
    "doc/architecture-audit/lean-toolchain",
    "doc/audit/zkp/lakefile.toml",
    "doc/audit/zkp/lean-toolchain",
    "doc/audit/zkp/Zkp.lean",
}


class GuardFailure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise GuardFailure(message)


def command(args, cwd=ROOT, capture=True):
    try:
        result = subprocess.run(args, cwd=cwd, check=True, text=True,
                                stdout=subprocess.PIPE if capture else None,
                                stderr=subprocess.STDOUT, timeout=600)
    except (OSError, subprocess.SubprocessError) as error:
        output = getattr(error, "stdout", "") or ""
        raise GuardFailure(f"command failed: {args!r}\n{output}\n{error}") from error
    return result.stdout or ""


def exact_keys(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys),
            f"{label}: expected exactly keys {sorted(keys)}")


def checked_path(root, value):
    require(isinstance(value, str) and value != "", "empty/non-string source path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.as_posix() == value
            and not any(part in {"", ".", ".."} for part in path.parts),
            f"noncanonical source path: {value!r}")
    resolved = (root / value).resolve()
    require(resolved.is_relative_to(root.resolve()), f"source escapes checkout: {value}")
    require(resolved.is_file(), f"missing source: {value}")
    return resolved


def without_comments_and_strings(source):
    """Preserve newlines, including through nested Lean block comments.

    This is a conservative admission/import inventory, not a Lean parser. Actual
    parsing and the trusted dependency check are always performed by Lean too.
    """
    output = []
    depth = 0
    quoted = False
    index = 0
    while index < len(source):
        pair = source[index:index + 2]
        char = source[index]
        if depth:
            if pair == "/-":
                depth += 1
                output.extend("  ")
                index += 2
                continue
            if pair == "-/":
                depth -= 1
                output.extend("  ")
                index += 2
                continue
            output.append("\n" if char == "\n" else " ")
        elif quoted:
            if char == "\\":
                output.extend("  ")
                index += 2
                continue
            if char == '"':
                quoted = False
            output.append("\n" if char == "\n" else " ")
        elif pair == "/-":
            depth = 1
            output.extend("  ")
            index += 2
            continue
        elif pair == "--":
            end = source.find("\n", index)
            if end < 0:
                end = len(source)
            output.extend(" " * (end - index))
            index = end
            continue
        elif char == '"':
            quoted = True
            output.append(" ")
        else:
            output.append(char)
        index += 1
    require(depth == 0 and not quoted, "unterminated Lean comment/string")
    return "".join(output)


def imports_of(source):
    clean = without_comments_and_strings(source)
    imports = set()
    for group in re.findall(r"^\s*import\s+([^\n]+)", clean, flags=re.MULTILINE):
        for name in group.split():
            require(QUALIFIED.fullmatch(name), f"unrecognized import: {name}")
            imports.add(name)
    return imports


def module_sources(root, project):
    paths = command(["git", "ls-files", "--cached", "--others", "--exclude-standard",
                     "--", project], cwd=root).splitlines()
    result = {}
    for path in paths:
        if path.endswith(".lean") and Path(path).name != "lakefile.lean":
            relative = PurePosixPath(path).relative_to(project).with_suffix("")
            module = ".".join(relative.parts)
            require(QUALIFIED.fullmatch(module), f"unrecognized Lean module path: {path}")
            result[module] = checked_path(root, path).read_text()
    require(result, f"no Lean modules found: {project}")
    return result


def check_coverage(root):
    count = 0
    for project, current in CURRENT.items():
        modules = module_sources(root, project)
        require(current in modules, f"current module missing: {current}")
        for module, source in modules.items():
            clean = without_comments_and_strings(source)
            admitted = re.findall(r"\b(?:sorry|admit|sorryAx|axiom)\b", clean)
            require(not admitted, f"explicit admission/axiom in {project}/{module}: {admitted}")
        # Current theorems must not import historical model hypotheses by accident.
        for name in imports_of(modules[current]):
            require(name in {"Init", "Std", "Lean"}
                    or name.startswith(("Init.", "Std.", "Lean.")),
                    f"current module imports nonstandard/historical model: {current}: {name}")
        if project == "doc/architecture-audit":
            require(ARCH_ROOTS <= set(modules),
                    f"missing architecture roots: {sorted(ARCH_ROOTS - set(modules))}")
            config = without_comments_and_strings((root / project / "lakefile.lean").read_text())
            defaults = re.findall(rf"@\[default_target\]\s*lean_lib\s+({IDENT})", config)
            require(len(defaults) == len(set(defaults)) and set(defaults) == set(modules),
                    f"architecture default targets do not cover every root: {sorted(modules)} vs {defaults}")
        else:
            reached = set()
            pending = ["Zkp"]
            while pending:
                name = pending.pop()
                if name in reached or name not in modules:
                    continue
                reached.add(name)
                pending.extend(imports_of(modules[name]))
            require(reached == set(modules),
                    f"Zkp root leaves modules unbuilt: {sorted(set(modules) - reached)}")
            config = (root / project / "lakefile.toml").read_text()
            require(re.search(r'^defaultTargets\s*=\s*\["Zkp"\]\s*$', config, re.MULTILINE),
                    "Zkp is no longer the default build target")
        count += len(modules)
    print(f"[lean-guard] {count} Lean modules covered; no explicit admissions; current imports isolated", flush=True)


def validate_manifest(root, manifest):
    exact_keys(manifest, {"schema_version", "audit_base_commit", "submodules", "files", "theorem_checks"}, "manifest")
    require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1,
            "unsupported manifest schema")
    base = manifest["audit_base_commit"]
    require(isinstance(base, str) and HEX40.fullmatch(base), "invalid audit base commit")
    command(["git", "merge-base", "--is-ancestor", base, "HEAD"], cwd=root)
    entries = manifest["files"]
    require(isinstance(entries, list) and entries, "empty source manifest")
    files = {}
    for entry in entries:
        exact_keys(entry, {"path", "sha256", "role"}, "source")
        path = entry["path"]
        actual = checked_path(root, path)
        require(path != MANIFEST and path not in files, f"self/duplicate source hash: {path}")
        require(entry["role"] in {"implementation", "model", "spec", "tooling"}, f"invalid source role: {path}")
        digest = entry["sha256"]
        require(isinstance(digest, str) and HEX64.fullmatch(digest), f"invalid source hash: {path}")
        require(hashlib.sha256(actual.read_bytes()).hexdigest() == digest,
                f"reviewed source changed: {path}; review model correspondence before refreshing manifest")
        files[path] = entry
    require(REQUIRED_TOOLING <= set(files), f"unhashed guard/build inputs: {sorted(REQUIRED_TOOLING - set(files))}")
    submodules = manifest["submodules"]
    require(isinstance(submodules, list) and submodules, "empty submodule pin list")
    pins = set()
    for pin in submodules:
        exact_keys(pin, {"path", "commit"}, "submodule pin")
        path, commit = pin["path"], pin["commit"]
        require(isinstance(path, str) and path not in pins, "duplicate/non-string submodule path")
        require(isinstance(commit, str) and HEX40.fullmatch(commit), "invalid submodule commit")
        require(not PurePosixPath(path).is_absolute() and ".." not in PurePosixPath(path).parts,
                "invalid submodule path")
        tree = command(["git", "ls-tree", "HEAD", "--", path], cwd=root).strip()
        require(tree == f"160000 commit {commit}\t{path}", f"manifest/gitlink mismatch: {path}")
        require(command(["git", "rev-parse", "HEAD"], cwd=root / path).strip() == commit,
                f"submodule checkout differs from manifest/gitlink: {path}")
        require(not command(["git", "status", "--porcelain"], cwd=root / path).strip(),
                f"submodule is modified: {path}")
        pins.add(path)
    require("contracts/lib/polygon-plonky2" in pins, "MLE/WHIR submodule pin is missing")
    checks = manifest["theorem_checks"]
    require(isinstance(checks, list) and len(checks) == len(CURRENT), "expected both current theorem modules")
    projects = set()
    for check in checks:
        exact_keys(check, {"project", "module", "theorems", "sources"}, "theorem check")
        project, module = check["project"], check["module"]
        require(isinstance(project, str) and project in CURRENT and project not in projects,
                "missing, duplicate, or unknown theorem project")
        require(module == CURRENT[project], f"wrong current theorem module: {module}")
        model = project + "/" + module.replace(".", "/") + ".lean"
        require(model in files and files[model]["role"] == "model", f"current model is unhashed: {model}")
        names = check["theorems"]
        require(isinstance(names, list) and names and all(isinstance(n, str) for n in names),
                f"empty/invalid theorem list: {module}")
        require(len(set(names)) == len(names) and all(QUALIFIED.fullmatch(n) and n.startswith(module + ".") for n in names),
                f"duplicate/unqualified/out-of-module theorem: {module}")
        declarations = re.findall(rf"\btheorem\s+({IDENT})\b",
                                  without_comments_and_strings((root / model).read_text()), re.MULTILINE)
        require(declarations and len(declarations) == len(names)
                and set(declarations) == {name.rsplit(".", 1)[-1] for name in names},
                f"manifest must audit every named current-module theorem: {module}")
        sources = check["sources"]
        require(isinstance(sources, list) and sources and all(isinstance(p, str) for p in sources),
                f"empty/invalid source mapping: {module}")
        require(len(set(sources)) == len(sources) and set(sources) <= set(files), f"unhashed/duplicate mapping: {module}")
        roles = {files[path]["role"] for path in sources}
        require({"implementation", "spec"} <= roles, f"model must map to implementation and spec: {module}")
        projects.add(project)
    print(f"[lean-guard] {len(files)} reviewed source hashes and {len(pins)} submodule pins verified", flush=True)
    return checks


def parse_axioms(output, theorem):
    # Require exactly one compiler-generated result per requested theorem; empty,
    # malformed, repeated, or unexpected output must never look like success.
    start = re.escape("'" + theorem + "'")
    pattern = start + r" (?:does not depend on any axioms|depends on axioms:\s*\[([^\]]*)\])"
    matches = list(re.finditer(pattern, output))
    require(len(matches) == 1, f"missing/ambiguous Lean axiom result: {theorem}")
    content = matches[0].group(1)
    axioms = set() if content is None or not content.strip() else {x.strip() for x in content.split(",")}
    require(axioms <= KERNEL_AXIOMS, f"unapproved transitive axioms in {theorem}: {sorted(axioms - KERNEL_AXIOMS)}")
    return axioms


def audit_theorems(root, checks):
    lake = shutil.which("lake")
    require(lake is not None, "lake not on PATH; install/use the pinned lean-toolchain")
    for project in CURRENT:
        command([lake, "build"], cwd=root / project, capture=False)
    # Temporary audit modules never rewrite checked-in proofs or golden outputs.
    with tempfile.TemporaryDirectory(prefix="intmax-lean-axioms-") as temp:
        for index, check in enumerate(checks):
            lines = ["import Lean", "import " + check["module"]]
            for theorem in check["theorems"]:
                lines.extend([
                    "run_cmd do",
                    "  let info ← Lean.getConstInfo `" + theorem,
                    "  match info with",
                    "  | .thmInfo _ => pure ()",
                    '  | _ => throwError "audit target is not a theorem"',
                    "#check " + theorem,
                    "#print axioms " + theorem,
                ])
            probe = Path(temp) / f"CurrentAxioms{index}.lean"
            probe.write_text("\n".join(lines) + "\n")
            output = command([lake, "env", "lean", str(probe)], cwd=root / check["project"])
            require("sorryAx" not in output and "declaration uses 'sorry'" not in output,
                    "Lean reported an admitted dependency")
            for theorem in check["theorems"]:
                axioms = parse_axioms(output, theorem)
                print(f"[lean-guard] {theorem}: {sorted(axioms)}", flush=True)


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def main():
    require(len(sys.argv) == 1, "this guard accepts no skip/override options")
    try:
        manifest = json.loads(checked_path(ROOT, MANIFEST).read_text(), object_pairs_hook=unique_json_object)
    except (OSError, json.JSONDecodeError) as error:
        raise GuardFailure(f"cannot read source manifest: {error}") from error
    checks = validate_manifest(ROOT, manifest)
    check_coverage(ROOT)
    audit_theorems(ROOT, checks)
    # Catch a build-time rewrite of anything on which the review was based.
    validate_manifest(ROOT, manifest)
    print("[lean-guard] PASS: complete model builds, reviewed-source pins, and current theorem axiom allowlist")
    print("[lean-guard] NOT proved: implementation refinement or cryptographic/environment hypotheses")


if __name__ == "__main__":
    try:
        main()
    except (GuardFailure, OSError, TypeError, ValueError, KeyError) as error:
        print(f"[lean-guard] FAIL: {error}", file=sys.stderr)
        sys.exit(1)
