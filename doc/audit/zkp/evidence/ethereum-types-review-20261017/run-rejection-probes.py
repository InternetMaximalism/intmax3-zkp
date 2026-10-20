#!/usr/bin/env python3
"""Run bounded invalid-witness probes in isolated local processes."""
import json
from pathlib import Path
import resource
import subprocess

ROOT = Path('/Users/andropov/repos/intmax3-zkp')
OUT = Path(__file__).resolve().parent
BIN = ROOT / 'target/release/ethereum-types-boundary-audit'
MODES = [
    'u64-add-overflow', 'u64-sub-underflow',
    'u256-add-overflow', 'u256-sub-underflow',
    'limb-range', 'byte-range', 'cmp-range', 'cmp-wrong-result',
]
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
results = []
for mode in MODES:
    p = subprocess.run([str(BIN), mode], cwd=ROOT, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    (OUT / f'{mode}.log').write_text(p.stdout)
    if p.returncode == 0 and f'REJECTED {mode}:' in p.stdout:
        outcome = 'rejected_with_error'
    elif p.returncode == -6 and 'panicked' in p.stdout:
        outcome = 'prover_aborted; inspect log and constraints separately'
    else:
        outcome = 'UNEXPECTED; manual investigation required'
    result = {'mode': mode, 'returncode': p.returncode, 'outcome': outcome}
    results.append(result)
    print(json.dumps(result), flush=True)
(OUT / 'rejection-results.json').write_text(json.dumps(results, indent=2) + '\n')
assert all(not r['outcome'].startswith('UNEXPECTED') for r in results)
