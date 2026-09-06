#!/usr/bin/env bash
# Kernel-check both complete corpora, then audit the current conditional models.
# The source manifest is a review/drift gate, NOT a proof of implementation refinement.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
exec python3 .github/ci/lean-safety-guard.py
