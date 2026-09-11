#!/usr/bin/env python3
"""Self-tests for check-ledger-writers.py: it must actually fail on a drifted tree.

Each case copies the real sources into a scratch tree, mutates one of them in a
line-count-preserving way (so the inventoried line numbers stay valid), and asserts the
guard's exit status and message.

Usage: python3 -B .github/ci/test-check-ledger-writers.py
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / ".github" / "ci" / "check-ledger-writers.py"
LEAN = Path("doc/audit/zkp/Zkp/Implementation/LedgerWriters.lean")
CONTRACTS = Path("contracts/src")

FAILURES = []


def require(condition, message):
    if not condition:
        FAILURES.append(message)


def make_tree(tmp):
    root = Path(tmp) / "tree"
    (root / CONTRACTS).mkdir(parents=True)
    (root / LEAN.parent).mkdir(parents=True)
    for path in sorted((ROOT / CONTRACTS).glob("*.sol")):
        shutil.copy(path, root / CONTRACTS / path.name)
    shutil.copy(ROOT / LEAN, root / LEAN)
    return root


def run(root):
    result = subprocess.run([sys.executable, "-B", str(CHECKER), str(root)],
                            capture_output=True, text=True)
    return result.returncode, result.stdout + result.stderr


def replace_comment_line(path, after, statement):
    """Overwrite the first comment-only line past `after` -- keeps every line number."""
    lines = path.read_text().split("\n")
    for index in range(after, len(lines)):
        stripped = lines[index].strip()
        if stripped.startswith("//") and not stripped.startswith("///"):
            lines[index] = statement
            path.write_text("\n".join(lines))
            return index + 1
    raise AssertionError("no comment-only line past %d in %s" % (after, path))


def case_clean_tree_passes(tmp):
    root = make_tree(tmp)
    code, output = run(root)
    require(code == 0, "unmutated tree must pass, got exit %d:\n%s" % (code, output))
    require("PASS" in output, "unmutated tree must report PASS:\n%s" % output)


def case_extra_delete_fails(tmp):
    root = make_tree(tmp)
    manager = root / CONTRACTS / "ChannelSettlementManager.sol"
    line = replace_comment_line(manager, 2400,
                                "        delete usedWithdrawalNullifiers[bytes32(0)];")
    code, output = run(root)
    require(code == 1, "an added `delete usedWithdrawalNullifiers[x]` must fail, got exit %d:\n%s"
            % (code, output))
    require("uninventoried write" in output and "usedWithdrawalNullifiers" in output,
            "the failure must name the uninventoried write:\n%s" % output)
    require(":%d" % line in output, "the failure must name line %d:\n%s" % (line, output))


def case_extra_increment_fails(tmp):
    root = make_tree(tmp)
    manager = root / CONTRACTS / "ChannelSettlementManager.sol"
    replace_comment_line(manager, 2400, "        totalCreditedOut[0]++;")
    code, output = run(root)
    require(code == 1, "an added `totalCreditedOut[0]++` must fail, got exit %d:\n%s"
            % (code, output))
    require("totalCreditedOut" in output, "the failure must name the variable:\n%s" % output)


def case_other_contract_fails(tmp):
    root = make_tree(tmp)
    other = root / CONTRACTS / "ChannelSettlementVerifier.sol"
    replace_comment_line(other, 0, "    // placeholder")
    text = other.read_text().split("\n")
    for index, line in enumerate(text):
        if line.strip() == "// placeholder":
            text[index] = "    function drift() external { receivedChannelFunds[0] = 1; }"
            break
    other.write_text("\n".join(text))
    code, output = run(root)
    require(code == 1, "a write from another contract must fail, got exit %d:\n%s"
            % (code, output))
    require("receivedChannelFunds" in output and "ChannelSettlementVerifier.sol" in output,
            "the failure must name the offending contract:\n%s" % output)


def case_stale_inventory_fails(tmp):
    root = make_tree(tmp)
    lean = root / LEAN
    text = lean.read_text()
    require('2231, "submitWithdrawalClaim"' in text,
            "the inventory literal no longer has the expected shape")
    lean.write_text(text.replace('2231, "submitWithdrawalClaim"',
                                '2232, "submitWithdrawalClaim"', 1))
    code, output = run(root)
    require(code == 1, "a drifted inventory line must fail, got exit %d:\n%s" % (code, output))
    require("stale inventory entry" in output,
            "the failure must report the stale inventory entry:\n%s" % output)


def case_moved_write_fails(tmp):
    root = make_tree(tmp)
    manager = root / CONTRACTS / "ChannelSettlementManager.sol"
    text = manager.read_text()
    require("usedWithdrawalNullifiers[claim.withdrawalNullifier] = true;" in text,
            "the pinned :2231 statement is no longer present verbatim")
    manager.write_text(text.replace("usedWithdrawalNullifiers[claim.withdrawalNullifier] = true;",
                                    "// the write was removed", 1))
    code, output = run(root)
    require(code == 1, "removing the inventoried write must fail, got exit %d:\n%s"
            % (code, output))
    require("stale inventory entry" in output,
            "removing a write must be reported as a stale inventory entry:\n%s" % output)


CASES = [
    case_clean_tree_passes,
    case_extra_delete_fails,
    case_extra_increment_fails,
    case_other_contract_fails,
    case_stale_inventory_fails,
    case_moved_write_fails,
]


def main():
    if not CHECKER.is_file():
        print("[ledger-writers-test] FAIL: missing %s" % CHECKER, file=sys.stderr)
        return 1
    for case in CASES:
        with tempfile.TemporaryDirectory(prefix="ledger-writers-") as tmp:
            case(tmp)
    if FAILURES:
        for message in FAILURES:
            print("[ledger-writers-test] FAIL: %s" % message, file=sys.stderr)
        return 1
    print("[ledger-writers-test] PASS: %d guard self-tests" % len(CASES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
