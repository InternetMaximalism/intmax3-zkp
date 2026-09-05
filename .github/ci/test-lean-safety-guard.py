#!/usr/bin/env python3
"""Small guard regressions; no proof generation and no production source mutation."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("lean_guard", Path(__file__).with_name("lean-safety-guard.py"))
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)
REAL_COMMAND = GUARD.command


class LeanGuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lean-guard-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.pin = "b" * 40
        self.submodule = "contracts/lib/polygon-plonky2"
        self.manifest = {"schema_version": 1, "audit_base_commit": "a" * 40,
                         "submodules": [{"path": self.submodule, "commit": self.pin}],
                         "files": [], "theorem_checks": []}
        for path in sorted(GUARD.REQUIRED_TOOLING):
            self.add_file(path, "tooling", "-- build input\n")
        self.add_file("contracts/src/Modeled.sol", "implementation", "// reviewed source\n")
        self.add_file("doc/detail2.md", "spec", "Reviewed specification\n")
        for project, module in GUARD.CURRENT.items():
            self.add_file(project + "/" + module.replace(".", "/") + ".lean", "model",
                          "import Std\nnamespace " + module + "\ntheorem checked : True := True.intro\nend " + module + "\n")
            self.manifest["theorem_checks"].append({
                "project": project, "module": module, "theorems": [module + ".checked"],
                "sources": ["contracts/src/Modeled.sol", "doc/detail2.md"],
            })
        self.mock_command = patch.object(GUARD, "command", side_effect=self.git_result)
        self.mock_command.start()
        self.addCleanup(self.mock_command.stop)

    def add_file(self, path, role, text):
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text)
        self.manifest["files"].append({"path": path, "role": role,
                                       "sha256": hashlib.sha256(file.read_bytes()).hexdigest()})

    def git_result(self, args, cwd=None, capture=True):
        if args[:3] == ["git", "merge-base", "--is-ancestor"]:
            return ""
        if args[:2] == ["git", "ls-tree"]:
            return f"160000 commit {self.pin}\t{self.submodule}\n"
        if args == ["git", "rev-parse", "HEAD"]:
            return self.pin + "\n"
        if args == ["git", "status", "--porcelain"]:
            return ""
        raise AssertionError(f"unexpected subprocess {args}")

    def validate(self, manifest=None):
        return GUARD.validate_manifest(self.root, self.manifest if manifest is None else manifest)

    def test_complete_manifest_is_accepted(self):
        self.assertEqual(len(self.validate()), 2)

    def test_changed_source_fails(self):
        (self.root / "contracts/src/Modeled.sol").write_text("// changed\n")
        with self.assertRaisesRegex(GUARD.GuardFailure, "reviewed source changed"):
            self.validate()

    def test_missing_file_fails(self):
        (self.root / "doc/detail2.md").unlink()
        with self.assertRaisesRegex(GUARD.GuardFailure, "missing source"):
            self.validate()

    def test_missing_or_empty_theorem_check_fails(self):
        for empty in ([], [self.manifest["theorem_checks"][0]]):
            manifest = copy.deepcopy(self.manifest)
            manifest["theorem_checks"] = empty
            with self.assertRaises(GUARD.GuardFailure):
                self.validate(manifest)
        self.manifest["theorem_checks"][0]["theorems"] = []
        with self.assertRaisesRegex(GUARD.GuardFailure, "empty/invalid theorem"):
            self.validate()

    def test_omitted_current_theorem_fails(self):
        check = self.manifest["theorem_checks"][0]
        check["theorems"] = [check["module"] + ".unrelated"]
        with self.assertRaisesRegex(GUARD.GuardFailure, "every named current-module theorem"):
            self.validate()

    def test_missing_source_mapping_fails(self):
        self.manifest["theorem_checks"][0]["sources"] = ["doc/detail2.md"]
        with self.assertRaisesRegex(GUARD.GuardFailure, "implementation and spec"):
            self.validate()

    def test_unhashed_guard_fails(self):
        self.manifest["files"] = [f for f in self.manifest["files"]
                                   if f["path"] != ".github/ci/lean-safety-guard.py"]
        with self.assertRaisesRegex(GUARD.GuardFailure, "unhashed guard/build inputs"):
            self.validate()

    def test_wrong_gitlink_fails(self):
        self.manifest["submodules"][0]["commit"] = "c" * 40
        with self.assertRaisesRegex(GUARD.GuardFailure, "manifest/gitlink mismatch"):
            self.validate()

    def test_missing_submodule_fails(self):
        self.manifest["submodules"] = []
        with self.assertRaisesRegex(GUARD.GuardFailure, "empty submodule"):
            self.validate()

    def test_duplicate_and_self_hash_fails(self):
        self.manifest["files"].append(copy.deepcopy(self.manifest["files"][0]))
        with self.assertRaisesRegex(GUARD.GuardFailure, "self/duplicate"):
            self.validate()

    def test_invalid_relative_path_fails(self):
        for path in ("../secret", "/tmp/secret", "doc/../secret", "doc//detail2.md"):
            with self.assertRaises(GUARD.GuardFailure):
                GUARD.checked_path(self.root, path)

    def test_kernel_allowlist_results(self):
        name = "ChannelSafetyCurrent.checked"
        empty = f"'{name}' does not depend on any axioms\n"
        allowed = f"'{name}' depends on axioms: [propext,\n Classical.choice, Quot.sound]\n"
        self.assertEqual(GUARD.parse_axioms(empty, name), set())
        self.assertEqual(GUARD.parse_axioms(allowed, name), GUARD.KERNEL_AXIOMS)

    def test_admission_and_extra_assumption_results_fail(self):
        name = "ChannelSafetyCurrent.checked"
        for axiom in ("sorryAx", "NewCryptographicAssumption", "Lean.ofReduceBool"):
            with self.assertRaisesRegex(GUARD.GuardFailure, "unapproved transitive axioms"):
                GUARD.parse_axioms(f"'{name}' depends on axioms: [{axiom}]", name)

    def test_missing_duplicate_or_malformed_results_fail(self):
        name = "ChannelSafetyCurrent.checked"
        good = f"'{name}' does not depend on any axioms\n"
        for output in ("", "Build completed successfully", good + good,
                       f"'{name}' depends on axioms: ["):
            with self.assertRaisesRegex(GUARD.GuardFailure, "missing/ambiguous"):
                GUARD.parse_axioms(output, name)

    def test_comment_aware_admission_and_import_scan(self):
        text = '/- sorry /- axiom -/ -/\n-- admit\nimport Std\n#check "sorry"\ntheorem sound : True := by trivial\n'
        clean = GUARD.without_comments_and_strings(text)
        self.assertNotIn("sorry", clean)
        self.assertNotIn("axiom", clean)
        self.assertEqual(GUARD.imports_of(text), {"Std"})
        self.assertIn("sorry", GUARD.without_comments_and_strings("example : True := by sorry"))

    def test_all_architecture_roots_must_be_default_targets(self):
        modules = {name: "import Std\n" for name in GUARD.ARCH_ROOTS}
        lakefile = self.root / "doc/architecture-audit/lakefile.lean"
        lakefile.write_text("@[default_target]\nlean_lib ChannelSafety21\n")
        with patch.object(GUARD, "module_sources", return_value=modules):
            with self.assertRaisesRegex(GUARD.GuardFailure, "default targets do not cover"):
                GUARD.check_coverage(self.root)

    def test_historical_import_into_current_module_fails(self):
        modules = {name: "import Std\n" for name in GUARD.ARCH_ROOTS}
        modules["ChannelSafetyCurrent"] = "import ChannelSafety21\n"
        with patch.object(GUARD, "module_sources", return_value=modules):
            with self.assertRaisesRegex(GUARD.GuardFailure, "nonstandard/historical"):
                GUARD.check_coverage(self.root)

    def test_duplicate_manifest_json_keys_fail(self):
        with self.assertRaisesRegex(GUARD.GuardFailure, "duplicate JSON key"):
            json.loads('{"schema_version": 0, "schema_version": 1}',
                       object_pairs_hook=GUARD.unique_json_object)

    def test_subprocess_failure_is_not_success(self):
        error = subprocess.CalledProcessError(1, ["lean"], output="type mismatch")
        with patch.object(GUARD.subprocess, "run", side_effect=error):
            with self.assertRaisesRegex(GUARD.GuardFailure, "command failed"):
                REAL_COMMAND(["lean"], cwd=self.root)


if __name__ == "__main__":
    unittest.main()
