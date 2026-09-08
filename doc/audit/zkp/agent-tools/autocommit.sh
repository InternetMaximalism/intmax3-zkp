#!/bin/bash
# Safety net: every 10 minutes commit any new/changed audit files as WIP on the current branch.
W="$(cd "$(dirname "$0")/../../../.." && pwd)"
cd "$W" || exit 1
while true; do
  sleep 600
  git add doc/audit/zkp/Zkp/Implementation doc/audit/zkp/line-map doc/audit/zkp/*.md .github/ci 2>/dev/null
  if ! git diff --cached --quiet; then
    git commit -q -m "wip(lean): autosave $(date +%H:%M) (unbuilt/unregistered agent output)" && echo "$(date +%T) committed $(git rev-parse --short HEAD)"
  fi
done
