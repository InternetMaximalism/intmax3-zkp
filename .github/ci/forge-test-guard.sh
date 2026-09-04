#!/usr/bin/env bash
#
# `forge test` with the two things `forge test` alone does not give you: proof that the run was
# not vacuous, and proof that the suites that guard the fund-impacting defects actually executed.
#
# WHY. `vm.skip(true)` makes a Foundry test report `Skipped` and STILL EXITS 0. Nearly every
# real-proof test in this repo self-skips when a fixture is absent — CloseLifecycleE2E.t.sol,
# WithdrawNativeE2E.t.sol, PartialWithdrawalPayout.t.sol, ReclaimStake.t.sol, C2CFullE2E.t.sol,
# C2CBlockHash.t.sol (doc/audit/exit-path-facade-sweep.md F10). A CI step that runs them with the
# fixtures missing is green, silent, and covers nothing. That is the same shape as every defect
# this repo shipped this month, so it is a hard failure here: ANY status other than Success fails
# the run, and the total and the per-suite counts must clear a floor.
#
# Usage:  .github/ci/forge-test-guard.sh            # from anywhere in the repo
# Env:    FORGE_TEST_ARGS  extra args passed verbatim to `forge test`

set -euo pipefail

fail() { printf '\n[forge-guard] FAIL: %s\n' "$*" >&2; exit 1; }

command -v jq >/dev/null || fail "jq is required to parse \`forge test --json\`"

cd "$(git rev-parse --show-toplevel)/contracts"

# ── Floors ──────────────────────────────────────────────────────────────────────────────────────
# Measured on the frozen audit30-08-2026 integration tree: 473 tests across 37 suites, 0 skipped
# (was 335/23 at audit28-08-2026). The floors are deliberately the measured values, not round numbers:
# DELETING a test is as much a regression as failing one, and this repo has a history of coverage
# silently evaporating. Raise them when tests are added.
MIN_TOTAL_TESTS=473
MIN_SUITES=37

# Suites that exist specifically to guard a defect that shipped. Each is named with the class it
# covers, and each MUST report at least this many passing tests. A rename, a deletion, or a
# whole-contract skip fails here rather than quietly reducing coverage to nothing.
#
#   DeployGuards      — the deploy scripts are executed and their RESULT inspected. Guards the
#                       "three VK initializers absent from the real-network deploy path" and the
#                       "1-second challenge period against a documented 86,400" defects. Nothing
#                       in `forge test` ever ran a deploy script before this file existed.
#   ClaimMleVerify    — the REAL MleVerifier (never MockMleVerifier) against the REAL checked-in
#                       claim fixtures. This is the check that catches gate-8: an on-chain
#                       evaluator that cannot evaluate the circuits this repo actually builds.
#   ExponentiationGate/…Adversarial
#                     — the ported gate-8 evaluator itself, unit vectors + adversarial probes.
#   CloseLifecycleE2E — the only real-prover-emitted-PI-vector-vs-Solidity-limb-layout check.
#                       Self-skips if any of three fixtures is missing; the status check below is
#                       what turns that into a failure instead of a green no-op.
#   MleE2E/MleFinalizeE2E
#                     — real MLE/WHIR verification of the validity/finalize path.
#   MemberSetUpdateE2E
#                     — audit28-08-2026 M-3/M-11. The ONLY real-PI-vector <-> Solidity-limb join
#                       outside the close statement: `applyMemberSetUpdate` against a REAL
#                       MemberSetUpdateCircuit proof, plus the two tests that check the msu VK and
#                       the close VK genuinely share the WHIR rail that
#                       `ChannelSettlementVerifier._verifyMsuMle` substitutes wholesale and never
#                       checks on chain. Until this line existed the whole file could be deleted
#                       while CI stayed green, and the rail-agreement assertions ran nowhere.
#   AuthorizedBurnFenwick
#                     — proof-bound newest-snapshot selection for authorized burns. Guards against
#                       selecting an older balance root after the signed burn snapshot exists.
#   FixtureParsingGuards
#                     — deployment input schema boundaries: gate-count/hole rejection, checked
#                       integer narrowing and canonical Goldilocks elements.
#
# `suite-key<TAB>minimum-tests`. A plain list rather than an associative array on purpose: macOS
# ships bash 3.2, and a CI guard nobody can run locally before pushing is a guard people route
# around.
REQUIRED_SUITES="\
test/DeployGuards.t.sol:DeployGuardsTest	27
test/MemberSetUpdateE2E.t.sol:MemberSetUpdateE2ETest	8
test/ClaimMleVerify.t.sol:ClaimMleVerifyTest	8
test/ExponentiationGate.t.sol:ExponentiationGateTest	13
test/ExponentiationGateAdversarial.t.sol:ZZAdversarialExpProbe	10
test/CloseLifecycleE2E.t.sol:CloseLifecycleE2ETest	2
test/MleE2E.t.sol:MleE2ETest	6
test/MleFinalizeE2E.t.sol:MleFinalizeE2ETest	2
test/AuthorizedBurnFenwick.t.sol:AuthorizedBurnSnapshotTest	7
test/FixtureParsingGuards.t.sol:FixtureParsingGuardsTest	17"

out="$(mktemp -t forge-test-json)"
trap 'rm -f "$out"' EXIT

echo "[forge-guard] forge test ${FORGE_TEST_ARGS:-}"
set +e
# shellcheck disable=SC2086
forge test --json ${FORGE_TEST_ARGS:-} > "$out"
forge_rc=$?
set -e

# `forge test --json` writes only JSON to stdout, so print a human summary ourselves.
jq -r 'to_entries[] | "  \(.key)  \(.value.test_results | length) test(s)"' "$out" | sort

total="$(jq '[.[] | .test_results | length] | add // 0' "$out")"
suites="$(jq 'keys | length' "$out")"
echo "[forge-guard] $total tests across $suites suites (forge exit $forge_rc)"

# ── 1. no test may report anything other than Success ───────────────────────────────────────────
# Covers Failure AND Skipped in one assertion. `forge test` exits 0 on Skipped; this does not.
bad="$(jq -r '
  to_entries[] as $s
  | $s.value.test_results | to_entries[]
  | select(.value.status != "Success")
  | "  \($s.key)::\(.key) -> \(.value.status) \(.value.reason // "")"
' "$out")"
if [ -n "$bad" ]; then
    printf '%s\n' "$bad" >&2
    fail "tests did not all report Success. A \"Skipped\" here means a fixture or precondition is \
missing and the test covered NOTHING while exiting 0 — treat it exactly as a failure."
fi

[ "$forge_rc" -eq 0 ] || fail "forge test exited $forge_rc"

# ── 2. anti-vacuity floors ──────────────────────────────────────────────────────────────────────
[ "$total" -ge "$MIN_TOTAL_TESTS" ] \
    || fail "only $total tests ran; expected at least $MIN_TOTAL_TESTS. Tests were deleted, \
filtered out, or a whole suite failed to compile into the run."
[ "$suites" -ge "$MIN_SUITES" ] \
    || fail "only $suites suites ran; expected at least $MIN_SUITES."

# ── 3. the named defect-guard suites really ran ─────────────────────────────────────────────────
while IFS="	" read -r suite want; do
    [ -n "${suite:-}" ] || continue
    got="$(jq --arg s "$suite" 'if has($s) then (.[$s].test_results | length) else 0 end' "$out")"
    [ "$got" -ge "$want" ] \
        || fail "guard suite '$suite' ran $got test(s), expected >= $want. This suite exists to \
catch a defect that reached a real deployment; it must not shrink or disappear silently."
    echo "[forge-guard] ok: $suite ($got tests)"
done <<< "$REQUIRED_SUITES"

echo "[forge-guard] PASS"
