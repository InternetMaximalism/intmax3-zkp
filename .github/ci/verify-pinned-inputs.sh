#!/usr/bin/env bash
#
# Guards the "the working copy built, a clean clone did not" defect class.
#
# WHY THIS EXISTS. The ExponentiationGate evaluator patch lived UNCOMMITTED inside the pinned
# `contracts/lib/polygon-plonky2` submodule. Every local `forge test` and `cargo test` was green
# because the working copy carried the patch; a clean clone did not build at all, and no check
# anywhere noticed. See doc/audit/why-gate8-was-missed.md and
# doc/audit/exit-path-facade-sweep.md F10 ("there is no CI, so 'green' has only ever meant 'green
# on someone's laptop').
#
# Four independent assertions, each closing one way that defect can recur:
#
#   1. Every submodule is checked out EXACTLY at the gitlink SHA recorded in this commit, with a
#      clean working tree. `git submodule status` prefixes '+' (checked out elsewhere), '-' (not
#      initialised) and 'U' (conflicts) are all hard failures.
#   2. Every submodule's own working tree is pristine. A job that patches a submodule in flight
#      reproduces the original defect exactly.
#   3. The pinned commit is an ancestor of the branch named in .gitmodules. `.gitmodules` carries
#      a first-hand warning about this: the `branch` was wrong for months and
#      `git submodule update --remote` silently moved to a tree with NO MLE Solidity verifier at
#      all. Reachability from the REMOTE is what proves the pin was actually pushed.
#   4. No tracked file is modified.
#
# The matching Cargo.lock assertion (`cargo metadata --locked`) is deliberately NOT here: it is a
# step in the Rust jobs, after the pinned toolchain is installed, so the Solidity job does not have
# to download a nightly toolchain to run this script.
#
# Note on the clean clone itself: on GitHub Actions every job starts from `actions/checkout`,
# which is a fresh clone from the remote into an empty workspace — there is no working copy to
# leak into it, and `submodules: recursive` FAILS THE JOB if a pinned submodule commit was never
# pushed. That is the clean-clone proof; this script makes it explicit and asserted instead of
# implicit, and adds the three checks checkout does not perform.

set -euo pipefail

fail() { printf '\n[pinned-inputs] FAIL: %s\n' "$*" >&2; exit 1; }
ok()   { printf '[pinned-inputs] ok: %s\n' "$*"; }

cd "$(git rev-parse --show-toplevel)"

# ── 1. submodules present, at the pin, unmodified ───────────────────────────────────────────────
status="$(git submodule status --recursive)"
[ -n "$status" ] || fail "\`git submodule status\` is empty — this repo HAS submodules (see .gitmodules)"
printf '%s\n' "$status"

while IFS= read -r line; do
    [ -n "$line" ] || continue
    prefix="${line:0:1}"
    path="$(printf '%s' "$line" | awk '{print $2}')"
    case "$prefix" in
        ' ') ;;
        '-') fail "submodule '$path' is NOT INITIALISED. Run: git submodule update --init --recursive" ;;
        '+') fail "submodule '$path' is checked out at a DIFFERENT commit than this repo pins. \
Never \`git submodule update --remote\`; run: git submodule update --init --recursive" ;;
        'U') fail "submodule '$path' has merge conflicts" ;;
        *)   fail "unrecognised \`git submodule status\` prefix '$prefix' for '$path'" ;;
    esac
done <<< "$status"
ok "all submodules initialised at the pinned commits"

# ── 2. no local modifications inside any submodule ──────────────────────────────────────────────
# THE defect: a patch that exists only in the working copy. `git submodule status` does not report
# dirty worktrees, so ask each submodule directly.
git submodule --quiet foreach --recursive '
    dirty="$(git status --porcelain)"
    if [ -n "$dirty" ]; then
        echo "[pinned-inputs] FAIL: submodule $displaypath has UNCOMMITTED changes:" >&2
        echo "$dirty" >&2
        echo "[pinned-inputs] A patch that lives only in a working copy is exactly the defect this repo shipped." >&2
        exit 1
    fi
'
ok "no submodule carries uncommitted changes"

# ── 3. the pin is reachable on the branch .gitmodules names ─────────────────────────────────────
# Guards the documented drift in .gitmodules: the `branch` key pointed at `mleintroduction` while
# the pinned commit was never on it, so `--remote` silently moved to a tree with no MLE verifier.
# Skipped only when the submodule was fetched shallow (no history to walk) — reported, never
# silently passed.
# NOTE: fed by a here-string, NOT a pipe. In a pipeline the loop body runs in a subshell, where
# `fail`'s `exit 1` would end only the subshell and the script would sail on — a fail-OPEN guard,
# which is the failure mode this whole file exists to prevent.
while read -r key path; do
    [ -n "${key:-}" ] || continue
    name="${key#submodule.}"; name="${name%.path}"
    branch="$(git config --file .gitmodules --get "submodule.${name}.branch" || true)"
    [ -n "$branch" ] || { echo "[pinned-inputs] note: '$path' pins no branch in .gitmodules — nothing to reconcile"; continue; }
    pin="$(git -C "$path" rev-parse HEAD)"
    if [ -f "$path/.git" ] || [ -d "$path/.git" ]; then
        if [ "$(git -C "$path" rev-parse --is-shallow-repository)" = "true" ]; then
            # A shallow submodule has no history to walk, so this assertion cannot run. On a
            # developer machine (`--depth 1` clones are common) that degrades to a warning. In CI
            # it is a HARD FAILURE: a guard that quietly downgrades itself is the same thing as no
            # guard, and the workflows set fetch-depth: 0 precisely so it can run.
            if [ "${PINNED_INPUTS_REQUIRE_FULL_HISTORY:-0}" = "1" ]; then
                fail "'$path' is a SHALLOW checkout, so the pin cannot be proven to be on \
origin/$branch. Check out with fetch-depth: 0 — this assertion must not be skipped in CI."
            fi
            echo "[pinned-inputs] WARNING: '$path' is a SHALLOW checkout; cannot prove $pin is on origin/$branch."
            echo "[pinned-inputs]          Re-clone with full history, or set PINNED_INPUTS_REQUIRE_FULL_HISTORY=1 to make this fatal."
            continue
        fi
        git -C "$path" fetch --quiet origin "$branch" \
            || fail "'$path': .gitmodules names branch '$branch', which does not exist on the remote"
        git -C "$path" merge-base --is-ancestor "$pin" FETCH_HEAD \
            || fail "'$path': pinned commit $pin is NOT on origin/$branch. Either the commit was \
never pushed (the exact ExponentiationGate defect), or .gitmodules names the wrong branch and a \
\`--remote\` update would silently move this submodule to unrelated code."
        ok "'$path' pin $pin is on origin/$branch"
    fi
done <<< "$(git config --file .gitmodules --get-regexp '^submodule\..*\.path$' || true)"

# ── 4. no tracked file is modified ──────────────────────────────────────────────────────────────
# Tracked-only (`-uno`) so the script stays usable on a developer machine with scratch files.
# The STRICT version — untracked files included — runs as a separate post-build step in the
# workflows, where a newly appeared file means a build wrote into the repo.
dirty="$(git status --porcelain -uno)"
[ -z "$dirty" ] || { printf '%s\n' "$dirty" >&2; fail "tracked files are modified in the checkout"; }
ok "no tracked file is modified"

echo "[pinned-inputs] PASS"
