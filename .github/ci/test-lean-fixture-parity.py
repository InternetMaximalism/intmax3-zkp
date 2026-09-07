#!/usr/bin/env python3
"""Offline unit tests for .github/ci/lean-fixture-parity.py.

These tests never invoke `lake`, `lean`, `git` or the network: they exercise the
pure helpers (keccak, limb packing, the Solidity recomputations, probe-output
parsing, field comparison, case construction) and stub the Lean runner.  The
suite is expected to pass with `lake` absent from PATH.

Run:  python3 .github/ci/test-lean-fixture-parity.py
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MODULE_PATH = _HERE / "lean-fixture-parity.py"

_spec = importlib.util.spec_from_file_location("lean_fixture_parity", _MODULE_PATH)
lfp = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
# Register before exec: dataclasses resolve annotations through sys.modules.
sys.modules["lean_fixture_parity"] = lfp
_spec.loader.exec_module(lfp)

DATA_DIR = _HERE.parents[1] / "contracts" / "test" / "data"


def _load(name):
    return json.loads((DATA_DIR / name).read_text(encoding="utf-8"))


def _pi(name):
    return [int(w, 16) for w in _load(name)["proof"]["publicInputs"]]


class KeccakTests(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(
            lfp.keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(
            lfp.keccak256(b"abc").hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
        self.assertEqual(
            lfp.keccak256(b"testing").hex(),
            "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02")

    def test_multi_block_input(self):
        # 200 bytes forces a second keccak-f permutation (rate = 136).
        data = bytes(range(200))
        self.assertEqual(len(lfp.keccak256(data)), 32)
        self.assertNotEqual(lfp.keccak256(data), lfp.keccak256(data[:199]))


class LimbTests(unittest.TestCase):
    def test_be_limbs_is_big_endian(self):
        self.assertEqual(lfp.be_limbs(1), [0, 0, 0, 0, 0, 0, 0, 1])
        self.assertEqual(lfp.be_limbs(1 << 224), [1, 0, 0, 0, 0, 0, 0, 0])

    def test_hex_limbs_matches_manual_split(self):
        text = "0x0000000a0000000b0000000c0000000d0000000e0000000f0000001000000011"
        self.assertEqual(lfp.hex_limbs(text), [10, 11, 12, 13, 14, 15, 16, 17])

    def test_address_limbs_is_five_words(self):
        self.assertEqual(
            lfp.address_limbs("0x0000000100000002000000030000000400000005"),
            [1, 2, 3, 4, 5])

    def test_be_value_inverts_be_limbs(self):
        value = 0x1234567890ABCDEF1122334455667788AABBCCDDEEFF00112233445566778899
        self.assertEqual(lfp.be_value(lfp.be_limbs(value)), value)

    def test_as_int_accepts_decimal_string_and_hex(self):
        self.assertEqual(lfp.as_int("77"), 77)
        self.assertEqual(lfp.as_int("0x4d"), 77)
        self.assertEqual(lfp.as_int(77), 77)
        with self.assertRaises(TypeError):
            lfp.as_int(True)

    def test_normalizers(self):
        self.assertEqual(lfp.norm_words([1, 2, 3]), "1,2,3")
        self.assertEqual(lfp.norm_num("0x10"), "16")
        self.assertEqual(lfp.norm_bool(True), "true")
        self.assertEqual(lfp.norm_bool(False), "false")


class SolidityRecomputationTests(unittest.TestCase):
    """The keccak recomputations must reproduce the prover's registered limbs."""

    WITHDRAWAL_PREFIXES = ["close_", "c2c_", "burn_", "", "sepolia_"]

    def test_withdrawal_pis_hash_matches_registered_public_inputs(self):
        checked = 0
        for prefix in self.WITHDRAWAL_PREFIXES:
            mle = DATA_DIR / f"{prefix}withdrawal_mle.json"
            payout = DATA_DIR / f"{prefix}withdrawal_payout.json"
            if not (mle.exists() and payout.exists()):
                continue
            checked += 1
            pi = _pi(mle.name)
            record = _load(payout.name)
            digest, preimage = lfp.withdrawal_pis_hash(record)
            self.assertEqual(len(preimage), 92)
            self.assertEqual(lfp.be_limbs(digest), pi[0:8],
                             f"{prefix}: pis_hash limbs differ")
            self.assertEqual(lfp.be_limbs(int(record["ext_commitment"], 16)), pi[8:16],
                             f"{prefix}: ext_commitment limbs differ")
            self.assertEqual(lfp.as_int(record["block_number"]), pi[16],
                             f"{prefix}: block_number differs")
        self.assertGreaterEqual(checked, 4)

    def test_pis_hash_is_masked_to_253_bits(self):
        record = _load("close_withdrawal_payout.json")
        digest, _ = lfp.withdrawal_pis_hash(record)
        self.assertLess(digest, 1 << 253)

    def test_fold_withdrawal_leaf_preimage_is_152_bytes(self):
        record = _load("close_withdrawal_payout.json")
        # A wrong-length field must be rejected by the assert, not silently packed.
        bad = dict(record["withdrawals"][0])
        bad["recipient"] = "0x00"
        with self.assertRaises(AssertionError):
            lfp.fold_withdrawal_leaf(b"\x00" * 32, bad)

    def test_validity_preimage_matches_registered_public_inputs(self):
        checked = 0
        for prefix in ["close_", "c2c_", "burn_", "", "sepolia_"]:
            lifecycle = DATA_DIR / f"{prefix}lifecycle.json"
            mle = DATA_DIR / f"{prefix}lifecycle_validity_mle.json"
            if not (lifecycle.exists() and mle.exists()):
                continue
            checked += 1
            vpis = _load(lifecycle.name)["vpis"]
            words = lfp.validity_u32_words(vpis)
            self.assertEqual(len(words), 41)
            preimage = lfp.validity_preimage(vpis)
            self.assertEqual(len(preimage), 164)
            self.assertEqual(lfp.be_limbs(int.from_bytes(lfp.keccak256(preimage), "big")),
                             _pi(mle.name), f"{prefix}: validity PI limbs differ")
        self.assertGreaterEqual(checked, 4)

    def test_e2e_fixture_pi_hash_matches_its_validity_record(self):
        e2e = _load("e2e_fixture.json")
        preimage = lfp.validity_preimage(e2e["validity_public_inputs"])
        self.assertEqual(lfp.keccak256(preimage).hex(), e2e["pi_hash"][2:])


class ProbeParsingTests(unittest.TestCase):
    def test_parses_fields_after_decode_ok(self):
        result = lfp.parse_probe_output(
            "FIELD input.length 103\nDECODE_OK\nFIELD channelId 1\nFIELD h1 1,2,3\n")
        self.assertTrue(result.ok)
        self.assertEqual(result.fields["input.length"], "103")
        self.assertEqual(result.fields["channelId"], "1")
        self.assertEqual(result.fields["h1"], "1,2,3")

    def test_decode_error_is_not_ok(self):
        result = lfp.parse_probe_output("FIELD input.length 12\nDECODE_ERROR invalidLength 103 12\n")
        self.assertFalse(result.ok)
        self.assertIn("invalidLength", result.error)

    def test_missing_marker_is_not_ok(self):
        result = lfp.parse_probe_output("FIELD channelId 1\n")
        self.assertFalse(result.ok)
        self.assertIn("DECODE_OK", result.error)

    def test_ignores_unrelated_lean_chatter(self):
        result = lfp.parse_probe_output(
            "info: probe.lean:3:0\nDECODE_OK\nFIELD a 1\nwarning: something\n")
        self.assertTrue(result.ok)
        self.assertEqual(result.fields, {"a": "1"})


class EvaluateTests(unittest.TestCase):
    def _case(self):
        case = lfp.Case(name="demo", module="M", decoder="d", words_source="w",
                        companion="c", probe="")
        case.expected = {"channelId": "1", "h1": "1,2,3"}
        case.not_comparable = {"opaque": "no companion record"}
        return case

    def test_all_matching_fields_pass(self):
        probe = lfp.ProbeResult(True, {"channelId": "1", "h1": "1,2,3", "opaque": "9"}, "", "")
        result = lfp.evaluate(self._case(), probe)
        self.assertTrue(result.ok)
        statuses = {f.field: f.status for f in result.fields}
        self.assertEqual(statuses["channelId"], lfp.PASS)
        self.assertEqual(statuses["h1"], lfp.PASS)
        self.assertEqual(statuses["opaque"], lfp.NOT_COMPARABLE)

    def test_mismatch_is_reported_not_papered_over(self):
        probe = lfp.ProbeResult(True, {"channelId": "2", "h1": "1,2,3"}, "", "")
        result = lfp.evaluate(self._case(), probe)
        self.assertFalse(result.ok)
        bad = [f for f in result.fields if f.status == lfp.FAIL]
        self.assertEqual([f.field for f in bad], ["channelId"])
        self.assertEqual(bad[0].lean, "2")
        self.assertEqual(bad[0].expected, "1")

    def test_missing_field_is_a_failure(self):
        probe = lfp.ProbeResult(True, {"channelId": "1"}, "", "")
        result = lfp.evaluate(self._case(), probe)
        self.assertFalse(result.ok)
        bad = [f for f in result.fields if f.status == lfp.FAIL]
        self.assertEqual([f.field for f in bad], ["h1"])
        self.assertIn("missing", bad[0].detail)

    def test_undecodable_fixture_is_a_failure(self):
        probe = lfp.ProbeResult(False, {}, "", "", "decoder rejected the fixture: invalidLength")
        result = lfp.evaluate(self._case(), probe)
        self.assertFalse(result.ok)
        self.assertIn("invalidLength", result.error)

    def test_not_comparable_alone_does_not_fail(self):
        case = self._case()
        case.expected = {}
        probe = lfp.ProbeResult(True, {"opaque": "9"}, "", "")
        self.assertTrue(lfp.evaluate(case, probe).ok)


class CaseConstructionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = lfp.build_cases(DATA_DIR)
        cls.by_name = {c.name: c for c in cls.cases}

    def test_required_fixtures_are_covered(self):
        for name in ("close_intent", "cancel_close", "withdrawal_claim", "post_close_claim",
                     "close_asset_backing"):
            self.assertIn(name, self.by_name, f"{name} case missing")
        self.assertGreaterEqual(
            sum(1 for n in self.by_name if n.startswith("withdrawal_chain[")), 4)
        self.assertGreaterEqual(
            sum(1 for n in self.by_name if n.startswith("validity[")), 5)

    def test_word_counts_are_the_documented_layouts(self):
        expected_len = {
            "close_intent": "103",
            "cancel_close": "29",
            "withdrawal_claim": "50",
            "post_close_claim": "57",
            "close_asset_backing": "26",
        }
        for name, length in expected_len.items():
            self.assertEqual(self.by_name[name].expected["input.length"], length)
        for name, case in self.by_name.items():
            if name.startswith("withdrawal_chain["):
                self.assertEqual(case.expected["input.length"], "17")

    def test_every_case_has_a_probe_that_only_imports(self):
        for case in self.cases:
            self.assertTrue(case.probe.strip(), case.name)
            self.assertIn("#eval", case.probe, case.name)
            for line in case.probe.splitlines():
                if line.startswith("import "):
                    self.assertTrue(line.startswith("import Zkp.Implementation."), line)
            # A probe must never contain proof-shaped or module-editing text.
            for forbidden in ("sorry", "axiom ", "theorem ", "@[simp]"):
                self.assertNotIn(forbidden, case.probe, f"{case.name}: {forbidden}")

    def test_probes_are_deterministic(self):
        again = {c.name: c.probe for c in lfp.build_cases(DATA_DIR)}
        for case in self.cases:
            self.assertEqual(case.probe, again[case.name], case.name)

    def test_reencode_expectation_is_the_original_prover_words(self):
        words = _pi("close_intent_mle.json")
        self.assertEqual(self.by_name["close_intent"].expected["reencoded"],
                         lfp.norm_words(words))

    def test_close_intent_expectations_come_from_the_companion_record(self):
        companion = _load("close_intent.json")
        case = self.by_name["close_intent"]
        self.assertEqual(case.expected["channelId"], str(companion["channel_id"]))
        self.assertEqual(case.expected["memberCount"], str(companion["member_count"]))
        self.assertEqual(case.expected["tokenFundsDigest"],
                         lfp.norm_words(lfp.hex_limbs(companion["token_funds_digest"])))
        # channel_fund_amount is a U256 amount, compared as the model's eight limbs.
        self.assertEqual(case.expected["genesisFund"],
                         lfp.norm_words(lfp.be_limbs(int(companion["channel_fund_amount"]))))

    def test_post_close_claim_marks_unrecorded_fields_not_comparable(self):
        case = self.by_name["post_close_claim"]
        self.assertIn("finalBalanceStateH1", case.not_comparable)
        self.assertIn("finalAccumulatorRoot", case.not_comparable)
        self.assertNotIn("finalBalanceStateH1", case.expected)

    def test_withdrawal_chain_case_checks_the_solidity_helpers(self):
        case = next(c for n, c in self.by_name.items() if n.startswith("withdrawal_chain["))
        self.assertEqual(case.expected["solidity.limbsMatchBytes32(pi,0,pisHash)"], "true")
        self.assertIn("solidity.limbsToBytes32(pi,8)", case.expected)
        self.assertIn("solidity.pi16", case.expected)
        self.assertIn("limbsToBytes32", case.probe)
        self.assertIn("limbsMatchBytes32", case.probe)

    def test_lean_nat_list_renders_a_lean_literal(self):
        self.assertEqual(lfp.lean_nat_list([1, 2, 3]), "[1, 2, 3]")
        self.assertEqual(lfp.lean_nat_list([]), "[]")

    def test_missing_data_dir_raises_a_handled_error(self):
        with self.assertRaises((FileNotFoundError, KeyError, ValueError)):
            lfp.build_cases(DATA_DIR / "does-not-exist")


class ReportingTests(unittest.TestCase):
    def _results(self):
        case = lfp.Case(name="demo", module="M", decoder="d", words_source="w",
                        companion="c", probe="", notes=["a note"])
        good = lfp.CaseResult(case, True, [lfp.FieldResult("a", lfp.PASS, "1", "1")])
        bad_case = lfp.Case(name="broken", module="M", decoder="d", words_source="w",
                            companion="c", probe="")
        bad = lfp.CaseResult(bad_case, False, [
            lfp.FieldResult("b", lfp.FAIL, "2", "1", "model value differs from fixture"),
            lfp.FieldResult("c", lfp.NOT_COMPARABLE, "9", None, "not recorded"),
        ])
        return [good, bad]

    def test_report_states_it_is_not_a_proof(self):
        text = lfp.format_report(self._results(), 1.0)
        self.assertIn("NOT a proof", text)

    def test_report_lists_failures_and_not_comparable(self):
        text = lfp.format_report(self._results(), 1.0)
        self.assertIn("FAIL            b", text)
        self.assertIn("not-comparable  c", text)
        self.assertIn("FAILED cases: broken", text)

    def test_json_report_round_trips(self):
        payload = lfp.results_to_json(self._results(), 1.0)
        json.dumps(payload)
        self.assertFalse(payload["cases"][1]["ok"])
        self.assertIn("not a refinement proof", payload["kind"])

    def test_error_case_is_rendered(self):
        case = lfp.Case(name="x", module="M", decoder="d", words_source="w",
                        companion="c", probe="")
        text = lfp.format_report([lfp.CaseResult(case, False, [], "lean failed")], 0.1)
        self.assertIn("ERROR", text)
        self.assertIn("FAILED cases: x", text)


class RunnerWithoutLakeTests(unittest.TestCase):
    """The suite itself must pass when `lake` is not installed."""

    def test_available_is_false_with_empty_path(self):
        saved = os.environ.get("PATH", "")
        try:
            os.environ["PATH"] = ""
            runner = lfp.LeanRunner(_HERE, elan_bin="")
            self.assertFalse(runner.available())
        finally:
            os.environ["PATH"] = saved

    def test_run_reports_a_missing_lake_instead_of_raising(self):
        saved = os.environ.get("PATH", "")
        try:
            os.environ["PATH"] = ""
            runner = lfp.LeanRunner(_HERE, elan_bin="")
            result = runner.run("#eval IO.println \"x\"", "probe_missing_lake")
            self.assertFalse(result.ok)
            self.assertIsNotNone(result.error)
        finally:
            os.environ["PATH"] = saved

    def test_main_exits_2_when_lake_is_absent(self):
        saved = os.environ.get("PATH", "")
        try:
            os.environ["PATH"] = ""
            code = lfp.main(["--data-dir", str(DATA_DIR), "--lean-dir", str(_HERE),
                             "--elan-bin", "", "--case", "cancel_close"])
            self.assertEqual(code, 2)
        finally:
            os.environ["PATH"] = saved

    def test_main_exits_2_on_an_unknown_case_filter(self):
        code = lfp.main(["--data-dir", str(DATA_DIR), "--case", "no-such-case"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
