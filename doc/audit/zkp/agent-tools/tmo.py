#!/usr/bin/env python3
"""macOS has no `timeout`; usage: python3 tmo.py <seconds> <cmd> [args...]  (exit 124 on timeout)"""
import subprocess, sys
secs = float(sys.argv[1]); cmd = sys.argv[2:]
try:
    r = subprocess.run(cmd, timeout=secs)
    sys.exit(r.returncode)
except subprocess.TimeoutExpired:
    print(f"tmo: killed after {secs}s: {' '.join(cmd)}", file=sys.stderr)
    sys.exit(124)
