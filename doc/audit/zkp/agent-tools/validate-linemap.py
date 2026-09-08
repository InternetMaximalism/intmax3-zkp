#!/usr/bin/env python3
"""Validate one line-map JSON against the repo's coverage rules and check that
every linked declaration/theorem exists in the built Lean module.
Usage: python3 validate-linemap.py [--no-probe] <path-to-map.json>   (any cwd)"""
import hashlib, importlib.util, json, os, pathlib, re, subprocess, sys, tempfile
sys.dont_write_bytecode = True
# Repo root derived from this file's location: <root>/doc/audit/zkp/agent-tools/<name>
ROOT = pathlib.Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location('cov', ROOT / '.github/ci/lean-line-coverage.py')
cov = importlib.util.module_from_spec(spec); spec.loader.exec_module(cov)
G = cov.G
p = pathlib.Path([a for a in sys.argv[1:] if not a.startswith('--')][0]).resolve()
m = json.loads(p.read_text(), object_pairs_hook=G.unique_json_object)
G.exact_keys(m, {"schema_version", "source", "source_sha256", "source_lines", "module",
                 "model", "refinement", "spans", "boundaries"}, "line map")
src = (ROOT / m['source']).read_bytes()
digest = hashlib.sha256(src).hexdigest()
lines = cov.physical_lines(src.decode('utf8'))
G.require(m['schema_version'] == 1, 'schema_version must be 1')
G.require(m['source_sha256'] == digest, f'source sha mismatch: expected {digest}')
G.require(m['source_lines'] == lines, f'source_lines mismatch: expected {lines}')
module = m['module']
G.require(module.startswith('Zkp.Implementation.'), 'bad module')
G.require(m['model'] == 'doc/audit/zkp/' + module.replace('.', '/') + '.lean', 'model path mismatch')
G.require((ROOT / m['model']).is_file(), 'model missing')
G.require(m['refinement'] == 'not-proved', 'refinement must be "not-proved"')
totals, decls, theorems = cov.validate_partition(m['spans'], lines, module)
b = m['boundaries']
G.require(isinstance(b, list) and b, 'boundaries empty')
names = set()
for x in b:
    G.exact_keys(x, {"name", "obligation", "discharged"}, 'boundary')
    G.require(x['name'].strip() and x['name'] not in names and x['obligation'].strip() and x['discharged'] is False, 'bad boundary')
    names.add(x['name'])
declared = set(G.declared_theorems((ROOT / m['model']).read_text()))
bad = [t for t in theorems if t.rsplit('.', 1)[-1] not in declared]
G.require(not bad, f'linked theorems not declared as `theorem` in module: {bad}')
print('partition OK', json.dumps(totals), 'decls', len(decls), 'theorems', len(theorems), '/', len(declared), 'declared')
if '--no-probe' in sys.argv:
    print('(probe skipped)'); sys.exit(0)
probe = ['import Lean', 'import ' + module]
for n in sorted(decls | theorems):
    probe.append('#check ' + n)
for n in sorted(theorems):
    probe += ['run_cmd do', '  let info ← Lean.getConstInfo `' + n, '  match info with',
              '  | .thmInfo _ => pure ()', '  | _ => throwError "line-map property is not a theorem"']
with tempfile.TemporaryDirectory() as d:
    f = pathlib.Path(d) / 'Probe.lean'; f.write_text('\n'.join(probe) + '\n')
    env = dict(os.environ, PATH='/Users/andropov/.elan/bin:' + os.environ['PATH'])
    r = subprocess.run(['lake', 'env', 'lean', str(f)], cwd=ROOT / 'doc/audit/zkp', env=env, text=True, capture_output=True)
    errs = [l for l in r.stdout.splitlines() + r.stderr.splitlines() if re.search(r':\d+:\d+: error', l) or l.startswith('error')]
    if r.returncode != 0 or errs:
        print('PROBE FAILED'); print('\n'.join(errs[:40])); sys.exit(1)
print('PROBE OK: all', len(decls | theorems), 'links resolve;', len(theorems), 'are theorems')
unlinked = sorted(declared - {t.rsplit('.', 1)[-1] for t in theorems})
print('declared theorems NOT linked from any span (allowed, but consider):', unlinked)
