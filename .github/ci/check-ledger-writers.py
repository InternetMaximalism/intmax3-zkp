#!/usr/bin/env python3
"""Fail-closed guard: the Solidity write sites of the five ledger variables.

`Zkp.Implementation.LedgerWriters` proves that no *modeled* entrypoint clears a used
withdrawal nullifier, lowers a funding cap, or rewrites a latched channel exit. That model
result is only worth something if the reviewed Solidity really has the write sites the Lean
inventory claims. This guard re-derives them from the sources on every CI run.

It scans `contracts/src/ChannelSettlementManager.sol` and
`contracts/src/CloseFundingMaterializer.sol` for EVERY write to

    usedWithdrawalNullifiers, receivedChannelFunds, totalCreditedOut,
    finalizedChannelFundAmount, materializedChannelExit

-- plain `=`, compound `+= -= *= /= %= |= &= ^= <<= >>=`, `delete`, prefix/postfix
`++`/`--`, plus anything inside an `assembly { ... }` block or on an `sstore` line -- and
asserts the resulting set of (file, variable, line, enclosing function) equals the
inventory parsed out of `flaggedWriteSites` in the Lean module. It then asserts that no
OTHER `.sol` file under `contracts/src` writes any of the five.

This is a text scan of reviewed sources, not a bytecode analysis. It cannot see a write
through an inherited library, a proxy upgrade, or a compiler bug; those stay inside the
source-refinement premise of `TrustBoundary`.

Usage: python3 -B .github/ci/check-ledger-writers.py [repo-root]
"""

import re
import sys
from pathlib import Path

LEAN_MODULE = Path("doc/audit/zkp/Zkp/Implementation/LedgerWriters.lean")
CONTRACTS = Path("contracts/src")
INVENTORIED_CONTRACTS = ("ChannelSettlementManager.sol", "CloseFundingMaterializer.sol")

VARIABLES = (
    "usedWithdrawalNullifiers",
    "receivedChannelFunds",
    "totalCreditedOut",
    "finalizedChannelFundAmount",
    "materializedChannelExit",
)

COMPOUND = ("<<=", ">>=", "+=", "-=", "*=", "/=", "%=", "|=", "&=", "^=")
COMPARISONS = ("==", "!=", "<=", ">=", "=>")

FAILURES = []


def fail(message):
    FAILURES.append(message)


def without_comments_and_strings(source):
    """Blank out comments and string/hex literals, preserving every newline and offset."""
    out = []
    i = 0
    n = len(source)
    while i < n:
        ch = source[i]
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            while i < n and source[i] != "\n":
                out.append(" ")
                i += 1
        elif ch == "/" and i + 1 < n and source[i + 1] == "*":
            out.append(" ")
            out.append(" ")
            i += 2
            while i < n and not (source[i] == "*" and i + 1 < n and source[i + 1] == "/"):
                out.append("\n" if source[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append(" ")
                out.append(" ")
                i += 2
        elif ch in ('"', "'"):
            quote = ch
            out.append(" ")
            i += 1
            while i < n and source[i] != quote:
                if source[i] == "\\" and i + 1 < n:
                    out.append(" ")
                    i += 1
                out.append("\n" if source[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append(" ")
                i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def line_of(source, offset):
    return source.count("\n", 0, offset) + 1


FUNCTION_HEAD = re.compile(r"\bfunction\s+([A-Za-z_$][A-Za-z_$0-9]*)")
SPECIAL_HEAD = re.compile(r"\b(constructor|receive|fallback)\s*\(")


def function_index(source):
    """(offset, name) for every function-like head, in source order."""
    heads = [(m.start(), m.group(1)) for m in FUNCTION_HEAD.finditer(source)]
    heads += [(m.start(), m.group(1)) for m in SPECIAL_HEAD.finditer(source)]
    heads.sort()
    return heads


def enclosing_function(heads, offset):
    name = "<file scope>"
    for start, candidate in heads:
        if start < offset:
            name = candidate
        else:
            break
    return name


def assembly_spans(source):
    """(start, end) offsets of every `assembly ... { ... }` block body."""
    spans = []
    for match in re.finditer(r"\bassembly\b", source):
        brace = source.find("{", match.end())
        if brace < 0:
            continue
        depth = 0
        i = brace
        while i < len(source):
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
                if depth == 0:
                    spans.append((brace, i))
                    break
            i += 1
    return spans


def skip_lvalue_tail(source, i):
    """Advance past `[...]` indices, `.member` accesses and whitespace of an lvalue."""
    n = len(source)
    while i < n:
        while i < n and source[i] in " \t\r\n":
            i += 1
        if i < n and source[i] == "[":
            depth = 0
            while i < n:
                if source[i] == "[":
                    depth += 1
                elif source[i] == "]":
                    depth -= 1
                    if depth == 0:
                        i += 1
                        break
                i += 1
            continue
        if i < n and source[i] == ".":
            i += 1
            while i < n and (source[i].isalnum() or source[i] in "_$"):
                i += 1
            continue
        break
    return i


def preceding_token(source, i):
    j = i - 1
    while j >= 0 and source[j] in " \t\r\n":
        j -= 1
    if j < 0:
        return ""
    end = j + 1
    if source[j].isalnum() or source[j] in "_$":
        while j >= 0 and (source[j].isalnum() or source[j] in "_$"):
            j -= 1
        return source[j + 1:end]
    return source[j]


def declaration_line(text):
    stripped = text.strip()
    return stripped.startswith("mapping") or stripped.startswith("uint") or \
        stripped.startswith("bytes") or stripped.startswith("function ")


def find_writes(path, source):
    """Every (variable, line, function) this file writes, plus a reason string."""
    clean = without_comments_and_strings(source)
    heads = function_index(clean)
    spans = assembly_spans(clean)
    lines = clean.split("\n")
    writes = {}

    for variable in VARIABLES:
        for match in re.finditer(r"\b%s\b" % re.escape(variable), clean):
            start, end = match.start(), match.end()
            line = line_of(clean, start)
            text = lines[line - 1]
            reason = None

            if any(lo < start < hi for lo, hi in spans):
                reason = "mentioned inside an assembly block"
            elif "sstore" in text:
                reason = "mentioned on an sstore line"
            else:
                before = preceding_token(clean, start)
                if before == "delete":
                    reason = "delete"
                elif before in ("++", "--"):
                    reason = "prefix %s" % before
                elif before == ".":
                    reason = None  # member access on another contract: a call, not a write
                else:
                    after = skip_lvalue_tail(clean, end)
                    tail = clean[after:after + 3]
                    if tail[:2] in ("++", "--"):
                        reason = "postfix %s" % tail[:2]
                    elif tail[:3] in COMPOUND:
                        reason = tail[:3]
                    elif tail[:2] in COMPOUND:
                        reason = tail[:2]
                    elif tail[:2] in COMPARISONS:
                        reason = None
                    elif tail[:1] == "=":
                        if declaration_line(text) and text.strip().startswith(("mapping", "uint", "bytes")):
                            reason = "declaration with initializer"
                        else:
                            reason = "="

            if reason is not None:
                key = (path.name, variable, line)
                writes[key] = (enclosing_function(heads, start), reason)
    return writes


LEAN_ENTRY = re.compile(
    r"⟨\s*\"([^\"]*)\"\s*,\s*\"([^\"]*)\"\s*,\s*(\d+)\s*,\s*\"([^\"]*)\"\s*,"
    r"\s*\"([^\"]*)\"\s*,\s*(?:some\s+\"([^\"]*)\"|none)\s*⟩"
)


def parse_lean_inventory(path):
    text = path.read_text()
    marker = "def flaggedWriteSites : List WriteSite := ["
    start = text.find(marker)
    if start < 0:
        fail("could not find `flaggedWriteSites` in %s" % path)
        return {}
    end = text.find("]", start)
    if end < 0:
        fail("unterminated `flaggedWriteSites` literal in %s" % path)
        return {}
    block = text[start + len(marker):end]
    inventory = {}
    for match in LEAN_ENTRY.finditer(block):
        contract, variable, line, entrypoint, modeled, step = match.groups()
        inventory[(contract, variable, int(line))] = (entrypoint, modeled, step or None)
    if len(inventory) != len(LEAN_ENTRY.findall(block)):
        fail("duplicate (contract, variable, line) entries in `flaggedWriteSites`")
    return inventory


def main():
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[2]

    lean = root / LEAN_MODULE
    if not lean.is_file():
        fail("missing Lean module %s" % LEAN_MODULE)
        return report()
    inventory = parse_lean_inventory(lean)

    if len(inventory) != 5:
        fail("expected 5 inventoried write sites, parsed %d" % len(inventory))
    if set(variable for (_, variable, _) in inventory) != set(VARIABLES):
        fail("the Lean inventory does not cover exactly the five flagged variables: %s"
             % sorted(set(variable for (_, variable, _) in inventory)))

    contracts = root / CONTRACTS
    if not contracts.is_dir():
        fail("missing %s" % CONTRACTS)
        return report()

    found = {}
    for path in sorted(contracts.glob("*.sol")):
        writes = find_writes(path, path.read_text())
        if path.name not in INVENTORIED_CONTRACTS:
            for (name, variable, line), (function, reason) in sorted(writes.items()):
                fail("%s:%d writes `%s` (%s) in `%s`; only %s may write the ledger variables"
                     % (name, line, variable, reason, function, " and ".join(INVENTORIED_CONTRACTS)))
            continue
        found.update(writes)

    for key in sorted(set(found) - set(inventory)):
        function, reason = found[key]
        fail("uninventoried write: %s:%d `%s` (%s) in `%s` -- add it to `flaggedWriteSites` "
             "and extend the frame theorems, or remove the write"
             % (key[0], key[2], key[1], reason, function))

    for key in sorted(set(inventory) - set(found)):
        entrypoint = inventory[key][0]
        fail("stale inventory entry: `flaggedWriteSites` claims %s:%d writes `%s` in `%s`, "
             "but no write was found there" % (key[0], key[2], key[1], entrypoint))

    for key in sorted(set(inventory) & set(found)):
        expected = inventory[key][0]
        actual, reason = found[key]
        if expected != actual:
            fail("enclosing function drift: %s:%d `%s` (%s) is in `%s`, inventory says `%s`"
                 % (key[0], key[2], key[1], reason, actual, expected))

    return report()


def report():
    if FAILURES:
        for message in FAILURES:
            print("[ledger-writers] FAIL: %s" % message, file=sys.stderr)
        print("[ledger-writers] FAIL: %d problem(s); the Lean `flaggedWriteSites` inventory "
              "and the Solidity sources disagree" % len(FAILURES), file=sys.stderr)
        return 1
    print("[ledger-writers] PASS: the 5 Solidity write sites of %s match `flaggedWriteSites`, "
          "and no other contract under %s writes them" % (", ".join(VARIABLES), CONTRACTS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
