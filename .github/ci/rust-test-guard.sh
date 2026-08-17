#!/usr/bin/env bash
#
# `cargo test` with the assertions that make a green result mean something in THIS repo.
#
# Three ways a cargo test step here can be green and cover nothing, all of them observed:
#
#   1. DEBUG MODE. Every heavy test is `#[cfg_attr(debug_assertions, ignore = "run with --release")]`
#      or `#![cfg(not(debug_assertions))]`. A `cargo test` without `--release` runs to completion,
#      prints "ok", and executes almost none of the suite. CLAUDE.md states this; nothing enforced
#      it. Guarded by (a) refusing to run without `--release`, and (b) an EXACT expected-ignored
#      count — a debug run makes `ignored` jump, a release run keeps it at the declared number.
#
#   2. SELF-SKIP AT RUNTIME. Most anvil/forge tests print "[skip] foundry … not found" or
#      "[skip] missing fixture …" and `return` — reported by libtest as PASSED. That is how
#      `tests/close_lifecycle_cli_e2e.rs`, described in its own header as "THE live verification
#      point for the close lifecycle", can pass on a machine with no Foundry and no fixtures.
#      Guarded by failing on any "[skip]" marker in the captured output.
#
#   3. ZERO TESTS. A filter that matches nothing, or a target that vanished, prints
#      "0 passed; 0 failed" and exits 0. Guarded by the expected-passed floor.
#
# Usage:
#   .github/ci/rust-test-guard.sh <min_passed> <exact_ignored> -- <cargo test args...>
#
# Example:
#   .github/ci/rust-test-guard.sh 41 0 -- cargo test --release --locked --test mle_gate_support

set -euo pipefail

fail() { printf '\n[rust-guard] FAIL: %s\n' "$*" >&2; exit 1; }

[ $# -ge 4 ] || fail "usage: $0 <min_passed> <exact_ignored> -- <cargo test args...>"
MIN_PASSED="$1"; shift
EXPECT_IGNORED="$1"; shift
[ "$1" = "--" ] || fail "expected '--' before the cargo command"; shift

# ── Guard 1a: release is not optional in this repo ──────────────────────────────────────────────
case " $* " in
    *" --release "*) ;;
    *) fail "refusing to run without --release. Every heavy test in this repo is gated on \
\`debug_assertions\`; a debug run reports \"ok\" while executing almost nothing (CLAUDE.md, \
\"Tests MUST run in release mode\")." ;;
esac
# --locked keeps Cargo.lock authoritative; see the REPRODUCIBILITY note in Cargo.toml.
case " $* " in
    *" --locked "*|*" --frozen "*) ;;
    *) fail "refusing to run without --locked: the git dependencies are pinned by Cargo.lock only." ;;
esac

log="$(mktemp -t rust-test-guard)"
trap 'rm -f "$log"' EXIT

# ── Force `--nocapture`. THIS IS LOAD-BEARING, NOT COSMETIC. ───────────────────────────────────
# libtest swallows the stdout/stderr of PASSING tests. The self-skip marker is printed by a test
# that then passes, so without --nocapture the "[skip]" check below can never fire and the guard
# is decoration. Verified: with Foundry off PATH,
# `cargo test --test deploy_settlement_chain_selection` reports "9 passed" and shows nothing;
# with --nocapture the same run prints nine "[skip] foundry `cast` not found" lines.
#
# Both mechanisms are used deliberately: the flag (stable, but must be appended after libtest's
# `--` separator) and the env var (works regardless of argument shape, though deprecated). If
# either stops working the other still exposes the markers.
args=("$@")
have_sep=0
for a in "$@"; do
    if [ "$a" = "--" ]; then have_sep=1; fi
done
[ "$have_sep" -eq 1 ] || args+=("--")
args+=("--nocapture")
export RUST_TEST_NOCAPTURE=1

echo "[rust-guard] ${args[*]}"
set +e
"${args[@]}" 2>&1 | tee "$log"
rc="${PIPESTATUS[0]}"
set -e
[ "$rc" -eq 0 ] || fail "cargo test exited $rc"

# ── Guard 2: the repo's own vacuous-pass marker ─────────────────────────────────────────────────
# Repo-wide convention: a test that cannot run its real body prints "[skip] …" and returns green.
# Every occurrence is a test that covered nothing. In CI the preconditions (Foundry on PATH,
# checked-in fixtures present) are guaranteed by the job, so a "[skip]" means the guarantee broke.
if grep -n '\[skip\]' "$log"; then
    fail "a test self-skipped at runtime and still reported PASS (see the \"[skip]\" lines above). \
The precondition it needs — Foundry on PATH, or a checked-in fixture — is missing in this job. \
Fix the environment; do not accept the green."
fi

# ── Guard 3: counts ─────────────────────────────────────────────────────────────────────────────
results="$(grep -c '^test result:' "$log" || true)"
[ "$results" -ge 1 ] || fail "no \"test result:\" line in the output — zero test binaries ran."

# Sum the per-binary tallies. Only `test result:` lines are considered, so a test whose own stdout
# happens to contain "3 passed" cannot inflate the count. awk, not bc: bc is not guaranteed on a
# GitHub runner image.
tally() { awk -v w="$1" '/^test result:/ { for (i = 1; i < NF; i++) if ($(i+1) ~ "^" w) s += $i } END { print s + 0 }' "$log"; }
passed="$(tally passed)"
failed="$(tally failed)"
ignored="$(tally ignored)"
echo "[rust-guard] $results binar(ies): $passed passed, $failed failed, $ignored ignored"

[ "${failed:-0}" -eq 0 ] || fail "$failed test(s) failed"
[ "${passed:-0}" -ge "$MIN_PASSED" ] \
    || fail "only ${passed:-0} test(s) passed; expected at least $MIN_PASSED. Tests were deleted, \
filtered out, or a target silently dropped out of the run."

# ── Guard 1b: exact ignored count ───────────────────────────────────────────────────────────────
# This is the debug-mode tripwire. It also fails if someone silences a failing test with
# `#[ignore]`, which is the cheapest way to make this CI green without fixing anything.
[ "${ignored:-0}" -eq "$EXPECT_IGNORED" ] \
    || fail "expected exactly $EXPECT_IGNORED ignored test(s), got ${ignored:-0}. Either this ran \
in DEBUG (where every release-gated test is auto-ignored and the suite covers nothing), or an \
\`#[ignore]\` was added/removed. If the change is intended, update the number in the workflow."

echo "[rust-guard] PASS"
