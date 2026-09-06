#!/usr/bin/env python3
"""Structural coverage regressions; no runtime contract/circuit experiments."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("line_coverage", Path(__file__).with_name("lean-line-coverage.py"))
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


class LineCoverageTests(unittest.TestCase):
    def setUp(self):
        self.module = "Zkp.Implementation.Sample"
        self.span = {"start": 1, "end": 3, "status": "translated", "label": "function",
                     "declarations": [self.module + ".function"], "theorems": [self.module + ".safe"],
                     "note": "Manual translation; external call is a boundary."}

    def validate(self, spans=None, lines=3):
        return C.validate_partition([self.span] if spans is None else spans, lines, self.module)

    def test_contiguous_partition(self):
        counts, declarations, theorems = self.validate()
        self.assertEqual(counts["translated"], 3)
        self.assertEqual(declarations, {self.module + ".function"})
        self.assertEqual(theorems, {self.module + ".safe"})

    def test_gap_and_overlap(self):
        for start in (0, 2):
            self.span["start"] = start
            with self.assertRaises(C.G.GuardFailure):
                self.validate()
        a, b = copy.deepcopy(self.span), copy.deepcopy(self.span)
        a.update(start=1, end=2)
        b.update(start=2, end=3)
        with self.assertRaises(C.G.GuardFailure):
            self.validate([a, b])

    def test_unmapped_trailing_lines(self):
        with self.assertRaisesRegex(C.G.GuardFailure, "trailing"):
            self.validate(lines=4)

    def test_source_range_must_be_integer(self):
        self.span.update(start=True)
        with self.assertRaises(C.G.GuardFailure):
            self.validate()

    def test_no_empty_translation(self):
        self.span["declarations"] = []
        with self.assertRaisesRegex(C.G.GuardFailure, "no Lean declaration"):
            self.validate()

    def test_nonproduction_not_counted_as_property(self):
        for status in ("non-executable", "test-only", "untranslated"):
            self.span["status"] = status
            with self.assertRaisesRegex(C.G.GuardFailure, "non-production"):
                self.validate()

    def test_no_cross_module_substitution(self):
        self.span["theorems"] = ["Zkp.Historical.unrelated"]
        with self.assertRaisesRegex(C.G.GuardFailure, "escapes"):
            self.validate()

    def test_comments_are_not_security_coverage(self):
        self.span.update(status="non-executable", declarations=[], theorems=[])
        counts, _, _ = self.validate()
        self.assertEqual(counts["translated"], 0)
        self.assertEqual(counts["non-executable"], 3)

    def test_source_scope(self):
        self.assertEqual(C.category("contracts/src/NewContract.sol"), "core")
        self.assertEqual(C.category("src/circuits/new_circuit.rs"), "core")
        self.assertEqual(C.category(C.SUBMODULE + "/mle/src/verifier_v2.rs"), "dependency")
        self.assertIsNone(C.category("node/example.js"))

    def test_physical_lines(self):
        self.assertEqual(C.physical_lines("a\nb\n"), 2)
        self.assertEqual(C.physical_lines("a\nb"), 2)

    def test_git_filename_quoting_cannot_hide_source(self):
        unusual = 'src/circuits/quote"and\nnewline.rs'
        with patch.object(C.G, "command", side_effect=[unusual + "\0", ""]):
            self.assertEqual(C.discover(Path("/fixture")), {unusual: "core"})


class InventoryValidationTests(unittest.TestCase):
    """Unit-test links/inventory admission independently of the separate guard.

    Actual Lean compiler resolution and reviewed-manifest validation still run
    in CI; mocks below do NOT stand in for those integration checks.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lean-line-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = "contracts/src/Sample.sol"
        self.module = "Zkp.Implementation.Sample"
        self.model = C.PROJECT + "/Zkp/Implementation/Sample.lean"
        self.map_path = C.PROJECT + "/line-map/sample.json"
        self.write(self.source, "function sample();\n")
        self.write(self.model, "-- compiler resolution is separately integration-tested\n")
        self.digest = hashlib.sha256((self.root / self.source).read_bytes()).hexdigest()
        self.mapping = {
            "schema_version": 1, "source": self.source, "source_sha256": self.digest,
            "source_lines": 1, "module": self.module, "model": self.model,
            "refinement": "not-proved",
            "spans": [{"start": 1, "end": 1, "status": "translated", "label": "sample",
                       "declarations": [self.module + ".sample"],
                       "theorems": [self.module + ".conditional_property"],
                       "note": "Manual representation, not a compiler proof."}],
            "boundaries": [{"name": "compiler", "obligation": "Source lowering is not proved.",
                            "discharged": False}],
        }
        self.inventory = {
            "schema_version": 1, "runtime_base_commit": "a" * 40,
            "formalization_base_commit": "b" * 40, "scope_note": "Explicit partial inventory.",
            "files": [{"path": self.source, "sha256": self.digest, "lines": 1,
                       "category": "core", "line_map": self.map_path}],
        }
        self.safety = {
            "files": [{"path": path, "role": role} for path, role in [
                (C.INVENTORY, "spec"), (self.source, "implementation"),
                (self.model, "model"), (self.map_path, "spec")]],
            "theorem_checks": [{"project": C.PROJECT, "module": self.module,
                                "theorems": [self.module + ".conditional_property"]}],
        }
        self.discovered = {self.source: "core"}
        self.actual_maps = [self.map_path]

    def write(self, path, text):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def validate(self):
        self.write(self.map_path, json.dumps(self.mapping))
        self.write(C.G.MANIFEST, json.dumps(self.safety))
        with patch.object(C, "discover", return_value=self.discovered), \
             patch.object(C.G, "validate_manifest", return_value=[]), \
             patch.object(C.G, "command", side_effect=lambda args, **kw:
                          "\0".join(self.actual_maps) if "ls-files" in args else ""):
            return C.validate(self.root, self.inventory)

    def test_valid_link_inventory(self):
        counts, categories, probes = self.validate()
        self.assertEqual(counts["translated"], 1)
        self.assertEqual(categories["core"], {"files": 1, "lines": 1})
        self.assertEqual(len(probes), 1)

    def test_changed_source_rejected(self):
        self.write(self.source, "function changed();\n")
        with self.assertRaisesRegex(C.G.GuardFailure, "source changed"):
            self.validate()

    def test_new_source_cannot_disappear(self):
        self.discovered["src/circuits/new.rs"] = "core"
        with self.assertRaisesRegex(C.G.GuardFailure, "omitted files"):
            self.validate()

    def test_wrong_reviewed_role_rejected(self):
        self.safety["files"][1]["role"] = "spec"
        with self.assertRaisesRegex(C.G.GuardFailure, "reviewed hashes"):
            self.validate()

    def test_refinement_cannot_be_self_declared(self):
        self.mapping["refinement"] = "proved"
        with self.assertRaisesRegex(C.G.GuardFailure, "no source-refinement"):
            self.validate()

    def test_dependency_cannot_be_silently_discharged(self):
        self.mapping["boundaries"][0]["discharged"] = True
        with self.assertRaisesRegex(C.G.GuardFailure, "unresolved premises"):
            self.validate()

    def test_unlisted_map_rejected(self):
        self.actual_maps.append(C.PROJECT + "/line-map/extra.json")
        with self.assertRaisesRegex(C.G.GuardFailure, "orphaned/unlisted"):
            self.validate()

    def test_linked_theorem_requires_axiom_audit(self):
        self.safety["theorem_checks"][0]["theorems"] = []
        with self.assertRaisesRegex(C.G.GuardFailure, "omitted from dependency audit"):
            self.validate()

    def test_map_source_digest_must_match(self):
        self.mapping["source_sha256"] = "0" * 64
        with self.assertRaisesRegex(C.G.GuardFailure, "source identity mismatch"):
            self.validate()

    def test_unmapped_file_is_untranslated(self):
        self.inventory["files"][0]["line_map"] = None
        self.actual_maps = []
        counts, _, probes = self.validate()
        self.assertEqual(counts["untranslated"], 1)
        self.assertEqual(counts["translated"], 0)
        self.assertEqual(probes, [])

    def test_duplicate_json_keys_rejected(self):
        self.write("duplicate.json", '{"schema_version": 1, "schema_version": 2}')
        with self.assertRaisesRegex(C.G.GuardFailure, "duplicate JSON"):
            C.load_json(self.root, "duplicate.json")


if __name__ == "__main__":
    unittest.main()
