#!/usr/bin/env python3
"""Renumber a line map after an INSERT-ONLY change to its source file.

    shift-linemap.py <map.json> <old-source-text-file> [--label=...] [--status=test-only]

The current source on disk is the NEW text; <old-source-text-file> holds the text the map was
written against (typically `git show <rev>:<path> > /tmp/old.rs`). The change must be
insert-only (no deleted or modified lines): every old line survives verbatim, in order. The
inserted lines become spans of the given status/label (default `test-only`, for `#[cfg(test)]`
probe code); every old span is shifted and split around the insertions; `source_sha256` and
`source_lines` are refreshed. Declarations/theorems/notes of a split span are carried onto each
part. Exit 1 if the change is not insert-only.
"""
import difflib, hashlib, json, pathlib, sys

def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    opts = dict(a[2:].split('=', 1) for a in sys.argv[1:] if a.startswith('--'))
    if len(args) != 2:
        raise SystemExit(__doc__)
    map_path, old_path = pathlib.Path(args[0]), pathlib.Path(args[1])
    label = opts.get('label', 'faithfulness probe: #[cfg(test)]-only wire captures for the Lean per-primitive model (2026-09-11)')
    status = opts.get('status', 'test-only')
    root = map_path.resolve().parents[4]
    mp = json.loads(map_path.read_text())
    src_path = root / mp['source']
    new_raw = src_path.read_bytes()
    new_lines = new_raw.decode('utf8').splitlines()
    old_lines = old_path.read_text(encoding='utf8').splitlines()
    if len(old_lines) != mp['source_lines']:
        raise SystemExit(f'old text has {len(old_lines)} lines but map says {mp["source_lines"]}')
    sm = difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False)
    # old line (1-based) -> new line (1-based); inserted new lines -> None
    old_to_new = {}
    inserted = set()
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            for k in range(i2 - i1):
                old_to_new[i1 + k + 1] = j1 + k + 1
        elif tag == 'insert':
            for j in range(j1, j2):
                inserted.add(j + 1)
        else:
            raise SystemExit(f'change is not insert-only: {tag} old {i1+1}-{i2} new {j1+1}-{j2}')
    assert len(old_to_new) == len(old_lines)
    # owner of each new line: (span index) or 'ins'
    owner = {}
    for idx, span in enumerate(mp['spans']):
        for ol in range(span['start'], span['end'] + 1):
            owner[old_to_new[ol]] = idx
    for nl in inserted:
        owner[nl] = 'ins'
    assert len(owner) == len(new_lines), (len(owner), len(new_lines))
    new_spans = []
    cur = None
    for nl in range(1, len(new_lines) + 1):
        o = owner[nl]
        if cur is not None and cur[0] == o and cur[2] == nl - 1:
            cur[2] = nl
            continue
        if cur is not None:
            new_spans.append(cur)
        cur = [o, nl, nl]
    new_spans.append(cur)
    out = []
    for o, s, e in new_spans:
        if o == 'ins':
            out.append({'start': s, 'end': e, 'status': status, 'label': label,
                        'declarations': [], 'theorems': [],
                        'note': 'Inserted after the model was written; compiled only under #[cfg(test)]. '
                                'Line citations in the Lean module docstrings refer to the pre-insertion numbering.'})
        else:
            base = dict(mp['spans'][o])
            base['start'], base['end'] = s, e
            out.append(base)
    mp['spans'] = out
    mp['source_sha256'] = hashlib.sha256(new_raw).hexdigest()
    mp['source_lines'] = len(new_lines)
    map_path.write_text(json.dumps(mp, indent=2, ensure_ascii=False) + '\n')
    print(f'{map_path.name}: {len(old_lines)} -> {len(new_lines)} lines, {len(inserted)} inserted, '
          f'{len(mp["spans"])} spans ({sum(1 for s in out if s["label"] == label)} probe spans)')

if __name__ == '__main__':
    main()
