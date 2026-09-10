#!/usr/bin/env python3
"""Auto-discover and register every unregistered Zkp.Implementation module.

- modules: doc/audit/zkp/Zkp/Implementation/*.lean not yet in guard CURRENT
- maps:    doc/audit/zkp/line-map/*.json whose "module" is such a module
- sources: from the maps; for map-less composition modules pass
           --compose=Zkp.Implementation.X:path1,path2  (paths must already be hashed implementation/spec files)
- extra tooling/doc files to hash: --tooling=path1,path2  (role "tooling")
- deliberately accept a CHANGED implementation source: --accept-source-change=path1,path2

Idempotent. An implementation-role hash never moves by accident: the script asserts it is unchanged
unless you name that exact path in --accept-source-change. Only do that after reviewing the model
correspondence for the file — the guard's own message says so, and the point of the assert is to make
the review a deliberate act rather than a side effect of re-running the registrar.
"""
import hashlib, importlib.util, json, pathlib, sys
sys.dont_write_bytecode = True
# Repo root derived from this file's location: <root>/doc/audit/zkp/agent-tools/<name>
ROOT = pathlib.Path(__file__).resolve().parents[4]
MANIFEST = ROOT / 'doc/audit/lean-current-source-manifest.json'
INVENTORY = ROOT / 'doc/audit/zkp/implementation-inventory.json'
ZKP = ROOT / 'doc/audit/zkp/Zkp.lean'
GUARD = ROOT / '.github/ci/lean-safety-guard.py'
PROJECT = 'doc/audit/zkp'
compose, tooling, accepted = {}, [], set()
for arg in sys.argv[1:]:
    if arg.startswith('--compose='):
        key, val = arg[len('--compose='):].split(':', 1); compose[key] = val.split(',')
    elif arg.startswith('--tooling='):
        tooling += arg[len('--tooling='):].split(',')
    elif arg.startswith('--accept-source-change='):
        accepted |= set(arg[len('--accept-source-change='):].split(','))
    else:
        raise SystemExit('unknown arg ' + arg)

def load_guard():
    spec = importlib.util.spec_from_file_location('guard', GUARD)
    g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g); return g
G = load_guard()
def sha(p): return hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
def load(p): return json.loads(p.read_text(), object_pairs_hook=G.unique_json_object)
def dump(p, obj): p.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + '\n')

current = set(G.CURRENT[PROJECT])
modules = ['Zkp.Implementation.' + f.stem for f in sorted((ROOT / PROJECT / 'Zkp/Implementation').glob('*.lean'))
           if 'Zkp.Implementation.' + f.stem not in current]
maps = {}
for f in sorted((ROOT / PROJECT / 'line-map').glob('*.json')):
    mp = load(f); maps.setdefault(mp['module'], []).append((PROJECT + '/line-map/' + f.name, mp['source']))
print('unregistered modules:', modules)

text = ZKP.read_text()
for m in modules:
    if f'import {m}\n' not in text: text += f'import {m}\n'
ZKP.write_text(text)

gtext = GUARD.read_text()
for m in modules:
    entry = f'        "{m}",\n'
    if entry not in gtext:
        idx = gtext.index('    ),\n}\n'); gtext = gtext[:idx] + entry + gtext[idx:]
GUARD.write_text(gtext)
G = load_guard()
assert all(m in G.CURRENT[PROJECT] for m in modules), 'CURRENT not updated'

inv = load(INVENTORY)
by_path = {e['path']: e for e in inv['files']}
for m in modules:
    for map_path, source in maps.get(m, []):
        if source not in by_path:
            src = (ROOT / source).read_bytes()
            by_path[source] = {'path': source, 'sha256': hashlib.sha256(src).hexdigest(),
                               'lines': len(src.decode('utf8').splitlines()), 'category': 'dependency', 'line_map': None}
            inv['files'].append(by_path[source]); print('inventory: added', source)
        e = by_path[source]
        assert e['sha256'] == sha(source), f'inventory implementation hash drift: {source}'
        e['line_map'] = map_path
for path in sorted(accepted):
    assert (ROOT / path).is_file(), f'accepted source does not exist: {path}'
    entry = by_path.get(path)
    if entry is None:
        # Manifest-only implementation source (e.g. a file the architecture models cite but the
        # line-coverage inventory does not scope). Only its manifest hash moves; there is no
        # inventory row or line map to re-review.
        print('inventory: accepted source is outside the line-coverage scope (manifest hash only):', path)
        continue
    raw = (ROOT / path).read_bytes()
    entry['sha256'] = hashlib.sha256(raw).hexdigest()
    entry['lines'] = len(raw.decode('utf8').splitlines())
    print('inventory: accepted source change', path, '->', entry['lines'], 'lines')
dump(INVENTORY, inv)

man = load(MANIFEST)
files = {e['path']: e for e in man['files']}
def ensure(path, role):
    if path in files:
        assert files[path]['role'] == role, f'role clash {path}: {files[path]["role"]} vs {role}'
        if role == 'implementation' and path not in accepted:
            assert files[path]['sha256'] == sha(path), f'IMPLEMENTATION HASH CHANGED: {path}'
        else:
            files[path]['sha256'] = sha(path)
    else:
        entry = {'path': path, 'sha256': sha(path), 'role': role}; man['files'].append(entry); files[path] = entry
for t in tooling: ensure(t, 'tooling')
checks = {c['module']: c for c in man['theorem_checks']}
for m in modules:
    model = f'{PROJECT}/Zkp/Implementation/{m.rsplit(".",1)[-1]}.lean'
    ensure(model, 'model')
    sources = []
    for map_path, source in maps.get(m, []):
        ensure(source, 'implementation'); ensure(map_path, 'spec'); sources += [map_path, source]
    for p in compose.get(m, []):
        assert p in files, f'compose source not hashed: {p}'; sources.append(p)
    assert sources, f'no sources for {m}: pass --compose={m}:path,path'
    roles = {files[p]['role'] for p in sources}
    assert {'implementation', 'spec'} <= roles, f'{m}: sources must include implementation and spec roles: {roles}'
    names = G.declared_theorems((ROOT / model).read_text())
    assert names and len(names) == len(set(names)), f'bad theorem inventory in {m}'
    entry = {'project': PROJECT, 'module': m, 'theorems': [f'{m}.{n}' for n in names], 'sources': sources}
    if m in checks: checks[m].update(entry)
    else: man['theorem_checks'].append(entry)
# Registered modules may have gained theorems since they were registered; refresh
# every implementation module's named-theorem list so the guard's inventory stays exact.
for c in man['theorem_checks']:
    if not c['module'].startswith('Zkp.Implementation.'):
        continue
    model_path = c['project'] + '/' + c['module'].replace('.', '/') + '.lean'
    c['theorems'] = [f"{c['module']}.{n}" for n in G.declared_theorems((ROOT / model_path).read_text())]
for path in list(files):
    if files[path]['role'] == 'implementation':
        if path in accepted:
            files[path]['sha256'] = sha(path)
        else:
            assert files[path]['sha256'] == sha(path), f'IMPLEMENTATION HASH CHANGED: {path}'
dump(MANIFEST, man)
man = load(MANIFEST)
for e in man['files']:
    if e['role'] != 'implementation': e['sha256'] = sha(e['path'])
dump(MANIFEST, man)
print('registered', len(modules), 'modules; theorem_checks:', len(man['theorem_checks']), 'files:', len(man['files']))
