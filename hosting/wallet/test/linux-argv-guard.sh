#!/usr/bin/env bash
# Start a program only if Linux would start it with these arguments.
#
# Linux refuses to exec a program when one argument is longer than 131,071 bytes (MAX_ARG_STRLEN,
# 32 pages including the terminating NUL), or when the arguments and environment together exceed
# ARG_MAX (2,097,152 bytes on the relay host). The call then fails with E2BIG, "Argument list too
# long" (os error 7). macOS has no per-argument limit, so a rehearsal on a Mac passed while every
# validity post on the Linux relay host failed this way: `cast publish <raw blob transaction>`
# passed ~526,000 hex characters as one argument (2026-11-08, 2026-11-25).
#
# public-chain-rehearsal.sh puts wrappers for cast and forge on PATH that run them through this
# guard, so the rehearsal refuses such a call as the host does.
#
# Usage: linux-argv-guard.sh <program> [args...]
set -u
program="$1"
shift
max_argument=131071
max_total=2097152

saved_lc_all="${LC_ALL-}"
LC_ALL=C # ${#arg} counts bytes, not characters
total=0
index=0
for argument in "$@"; do
  index=$((index + 1))
  length=${#argument}
  if [ "$length" -gt "$max_argument" ]; then
    echo "linux-argv-guard: $(basename "$program") argument $index is $length bytes; Linux refuses any argument over $max_argument bytes: Argument list too long (os error 7)" >&2
    exit 126
  fi
  total=$((total + length + 1))
done
if [ -n "$saved_lc_all" ]; then LC_ALL="$saved_lc_all"; else unset LC_ALL; fi
environment=$(env | wc -c)
if [ $((total + environment)) -gt "$max_total" ]; then
  echo "linux-argv-guard: $(basename "$program") arguments ($total bytes) and environment ($environment bytes) exceed Linux's $max_total: Argument list too long (os error 7)" >&2
  exit 126
fi
exec "$program" "$@"
