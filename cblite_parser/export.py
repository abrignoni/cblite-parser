"""Write a Couchbase Lite database out as a self-contained HTML page and CSV files.

``export(store_path, out_dir)`` creates ``out_dir`` (which must not exist or must be empty)
and writes:

``index.html``             one page, no network access: the database's own records, then
                           each collection as a filterable table whose rows expand to the
                           full body and the revision tree, then the blobs, with image blobs
                           shown in place
``documents.csv``          one row per document, the body as compact JSON
``revisions.csv``          one row per revision of every revision tree
``blobs.csv``              one row per blob reference, then each orphan blob file
``export_info.json``       what was exported, when, by which version, and the SHA-256 of
                           every source file read
``blobs/``                 a copy of each blob file that sniffs as a JPEG, PNG, GIF or WebP
                           image, named by its SHA-1, for the page to show

Every value from the database is evidence-controlled text, so the page escapes all of it,
its script only reads ``textContent`` to filter rows, and a Content-Security-Policy keeps it
from loading anything but its own images.
"""
import base64
import csv
import datetime
import hashlib
import html
import json
import math
import os
import shutil

from . import __version__, Store, VERSIONING

_IMAGE_MAGIC = (
    (b'\xff\xd8\xff', 'jpg'),
    (b'\x89PNG\r\n\x1a\n', 'png'),
    (b'GIF87a', 'gif'),
    (b'GIF89a', 'gif'),
)


def jsonable(value):
    """Turn a decoded Fleece value into something json.dumps writes as strict JSON."""
    if isinstance(value, bytes):
        return {'$base64': base64.b64encode(value).decode('ascii')}
    if isinstance(value, float) and not math.isfinite(value):
        return {'$float': repr(value)}
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [jsonable(v) for v in value]
    if value is not None and not isinstance(value, (str, int, float, bool)):
        return repr(value)
    return value


def _compact(value):
    return json.dumps(jsonable(value), ensure_ascii=False, allow_nan=False, separators=(',', ':'))


def _pretty(value):
    return json.dumps(jsonable(value), ensure_ascii=False, allow_nan=False, indent=2)


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _sniff_image(path):
    with open(path, 'rb') as handle:
        head = handle.read(16)
    for magic, ext in _IMAGE_MAGIC:
        if head.startswith(magic):
            return ext
    if head[:4] == b'RIFF' and head[8:12] == b'WEBP':
        return 'webp'
    return None


def _e(value):
    return html.escape('' if value is None else str(value), quote=True)


_CSS = '''
:root { --bg:#fff; --fg:#1d1d1f; --muted:#6e6e73; --line:#d2d2d7; --head:#f5f5f7; --accent:#0a5cc2; --bad:#b3261e; }
@media (prefers-color-scheme: dark) { :root { --bg:#161617; --fg:#f5f5f7; --muted:#a1a1a6; --line:#3a3a3c; --head:#232325; --accent:#6aa7ff; --bad:#ff8a80; } }
* { box-sizing: border-box; }
body { margin: 0 auto; max-width: 1400px; padding: 16px; background: var(--bg); color: var(--fg);
       font: 14px/1.45 -apple-system, "Segoe UI", Roboto, sans-serif; }
h1 { font-size: 22px; margin: 4px 0 2px; } h2 { font-size: 18px; margin: 28px 0 8px; }
.muted { color: var(--muted); } code, pre { font: 12px/1.4 ui-monospace, Menlo, Consolas, monospace; }
pre { margin: 6px 0; padding: 8px; background: var(--head); border-radius: 6px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; }
table { border-collapse: collapse; width: 100%; } th, td { border-bottom: 1px solid var(--line); padding: 5px 8px; text-align: left; vertical-align: top; }
th { background: var(--head); position: sticky; top: 0; font-weight: 600; }
td.body { max-width: 520px; } summary { cursor: pointer; color: var(--accent); }
.wrap { overflow-x: auto; } .bad { color: var(--bad); font-weight: 600; }
input[type=search] { width: 100%; max-width: 420px; padding: 6px 8px; margin: 4px 0 8px; border: 1px solid var(--line);
                     border-radius: 6px; background: var(--bg); color: var(--fg); }
img.blob { max-width: 220px; max-height: 220px; display: block; margin-top: 4px; border: 1px solid var(--line); }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; } dt { color: var(--muted); } dd { margin: 0; word-break: break-all; }
'''

_JS = '''
var DOCS = JSON.parse(document.getElementById('docdata').textContent);
function el(tag, text, cls) { var e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; }
function pretty(v) { return JSON.stringify(v, null, 2); }
document.querySelectorAll('details[data-doc]').forEach(function (d) {
  d.addEventListener('toggle', function () {
    var box = d.querySelector('.lazy');
    if (!d.open || box.dataset.done) return;
    box.dataset.done = '1';
    var doc = DOCS[+d.dataset.doc];
    if (doc.body !== null) box.appendChild(el('pre', pretty(doc.body)));
    if (doc.error) box.appendChild(el('pre', doc.error, 'bad'));
    if (doc.extra) box.appendChild(el('p', doc.extra, 'muted'));
    if (!doc.revisions.length) return;
    box.appendChild(el('p', 'Revision tree, current first', 'muted'));
    var t = el('table'), head = t.createTHead().insertRow(), body = t.createTBody();
    ['#', 'revid', 'parent', 'flags', 'sequence', 'body'].forEach(function (h) { head.appendChild(el('th', h)); });
    doc.revisions.forEach(function (r, i) {
      var row = body.insertRow();
      [i, r[0], r[1] === null ? '' : r[1], r[2], r[3]].forEach(function (v) { row.insertCell().textContent = v; });
      var cell = row.insertCell();
      cell.textContent = i === 0 ? 'current' : (r[4] ? 'kept' : '');
      if (r[4] && r[5] !== null) cell.appendChild(el('pre', pretty(r[5])));
      if (r[6]) cell.appendChild(el('pre', r[6], 'bad'));
    });
    box.appendChild(t);
  });
});
// The filter matches each row's visible text plus its full body and any kept older bodies,
// which are not in the page until a row is opened. Built once, on first use.
document.querySelectorAll('input[data-table]').forEach(function (box) {
  var rows = document.getElementById(box.dataset.table).tBodies[0].rows;
  var count = document.getElementById(box.dataset.table + '-count');
  var haystack = null, timer = null;
  function build() {
    haystack = [];
    for (var i = 0; i < rows.length; i++) {
      var text = rows[i].textContent, det = rows[i].querySelector('details[data-doc]');
      if (det) {
        var doc = DOCS[+det.dataset.doc];
        text += ' ' + JSON.stringify(doc.body);
        doc.revisions.forEach(function (r) { if (r[4]) text += ' ' + JSON.stringify(r[5]); });
      }
      haystack.push(text.toLowerCase());
    }
  }
  function apply() {
    if (!haystack) build();
    var q = box.value.toLowerCase(), shown = 0;
    for (var i = 0; i < rows.length; i++) {
      var hit = !q || haystack[i].indexOf(q) !== -1;
      rows[i].hidden = !hit; if (hit) shown++;
    }
    count.textContent = shown + ' of ' + rows.length;
  }
  box.addEventListener('input', function () { clearTimeout(timer); timer = setTimeout(apply, 150); });
});
'''


def export(store_path, out_dir):
    """Export the database at ``store_path`` into the new directory ``out_dir``.

    Returns the dict written to ``export_info.json``. Raises ``FileExistsError`` when
    ``out_dir`` exists and is not empty, and ``CBLiteError`` when the store cannot be read.
    """
    if os.path.exists(out_dir) and (not os.path.isdir(out_dir) or os.listdir(out_dir)):
        raise FileExistsError(f'{out_dir} exists and is not empty; choose a new folder')
    with Store(store_path) as store:
        os.makedirs(out_dir, exist_ok=True)
        docs = list(store.documents())
        blob_rows = list(store.blobs())
        orphans = store.orphan_blob_files()
        sources = [store.db_path + s for s in ('', '-wal', '-shm') if os.path.isfile(store.db_path + s)]
        info = {
            'tool': 'cblite-parser', 'version': __version__,
            'generated_utc': datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
            'source': os.path.abspath(store.bundle),
            'source_files': [{'path': os.path.abspath(p), 'bytes': os.path.getsize(p), 'sha256': _sha256(p)}
                             for p in sources],
            'versioning': store.versioning, 'versioning_name': VERSIONING.get(store.versioning),
            'shared_keys': len(store.shared_keys) if store.shared_keys is not None else None,
            'collections': {}, 'blob_references': len(blob_rows), 'orphan_blob_files': len(orphans),
        }
        for doc in docs:
            entry = info['collections'].setdefault(doc.collection, {'documents': 0, 'tombstones': 0})
            entry['tombstones' if doc.tombstone_table else 'documents'] += 1

        images = _copy_images(blob_rows, store.bundle, orphans, out_dir)
        _write_csv(out_dir, docs, blob_rows, orphans, store.bundle)
        _write_html(out_dir, store, info, docs, blob_rows, orphans, images)
        info['files'] = sorted(os.path.relpath(os.path.join(dp, f), out_dir)
                               for dp, _dn, fn in os.walk(out_dir) for f in fn) + ['export_info.json']
        with open(os.path.join(out_dir, 'export_info.json'), 'w', encoding='utf-8') as handle:
            json.dump(jsonable(info), handle, indent=2, ensure_ascii=False)
    return info


def _copy_images(blob_rows, bundle, orphans, out_dir):
    """Copy every blob file that sniffs as an image into blobs/, named by its SHA-1 hex.
    Returns {source path: relative path in the export}."""
    images = {}
    paths = {p for _d, _r, p, _m in blob_rows if p}
    paths |= {os.path.join(bundle, 'Attachments', name) for name in orphans}
    for path in sorted(paths):
        ext = _sniff_image(path)
        if not ext:
            continue
        digest = hashlib.sha1()
        with open(path, 'rb') as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b''):
                digest.update(chunk)
        name = digest.hexdigest() + '.' + ext
        os.makedirs(os.path.join(out_dir, 'blobs'), exist_ok=True)
        shutil.copyfile(path, os.path.join(out_dir, 'blobs', name))
        images[path] = 'blobs/' + name
    return images


def _write_csv(out_dir, docs, blob_rows, orphans, bundle):
    with open(os.path.join(out_dir, 'documents.csv'), 'w', newline='', encoding='utf-8') as handle:
        out = csv.writer(handle)
        out.writerow(['collection', 'key', 'sequence', 'revid', 'flags', 'deleted', 'tombstone_table',
                      'expiration_utc', 'revisions', 'older_bodies', 'body_error', 'body_json'])
        for doc in docs:
            out.writerow([doc.collection, doc.key, doc.sequence, doc.revid, ' '.join(doc.flags),
                          doc.deleted, doc.tombstone_table,
                          doc.expiration_utc.isoformat() if doc.expiration_utc else '',
                          len(doc.revisions), sum(1 for r in doc.revisions[1:] if r.has_body),
                          doc.body_error or '', _compact(doc.body) if doc.body is not None else ''])
    with open(os.path.join(out_dir, 'revisions.csv'), 'w', newline='', encoding='utf-8') as handle:
        out = csv.writer(handle)
        # the current revision's body is documents.csv body_json; only older bodies are written here
        out.writerow(['collection', 'key', 'index', 'revid', 'parent', 'flags', 'sequence', 'has_body',
                      'body_error', 'body_json'])
        for doc in docs:
            for rev in doc.revisions:
                out.writerow([doc.collection, doc.key, rev.index, rev.revid,
                              '' if rev.parent is None else rev.parent, ' '.join(rev.flags), rev.sequence,
                              rev.has_body, rev.body_error or '',
                              _compact(rev.body) if rev.index and rev.has_body and rev.body is not None else ''])
    with open(os.path.join(out_dir, 'blobs.csv'), 'w', newline='', encoding='utf-8') as handle:
        out = csv.writer(handle)
        out.writerow(['collection', 'key', 'path', 'digest', 'length', 'content_type', 'inline_bytes',
                      'file', 'sha1_matches', 'orphan'])
        for doc, ref, path, match in blob_rows:
            out.writerow([doc.collection, doc.key, ref.path, ref.digest or '',
                          '' if ref.length is None else ref.length, ref.content_type or '',
                          '' if ref.inline_bytes is None else ref.inline_bytes, path or '',
                          '' if match is None else match, False])
        for name in orphans:
            out.writerow(['', '', '', '', '', '', '', os.path.join(bundle, 'Attachments', name), '', True])


def _doc_payload(doc):
    """What a row's expanded view shows, rendered by the page's script with textContent."""
    return {
        'body': jsonable(doc.body), 'error': doc.body_error, 'extra': doc.extra_note,
        # [revid, parent, flags, sequence, kept, body, error]: arrays, because a large store
        # holds over a hundred thousand revisions and repeated field names doubled the page
        'revisions': [[r.revid, r.parent, ' '.join(r.flags), r.sequence, bool(r.index and r.has_body),
                       jsonable(r.body) if r.index and r.has_body else None, r.body_error]
                      for r in doc.revisions],
    }


def _script_json(value):
    """JSON safe to place inside a script element: no '<', '>' or '&' survives literally."""
    text = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':'))
    return text.replace('&', '\\u0026').replace('<', '\\u003c').replace('>', '\\u003e')


def _write_html(out_dir, store, info, docs, blob_rows, orphans, images):
    payload = []
    blobs_by_doc = {}
    for doc, ref, path, match in blob_rows:
        blobs_by_doc.setdefault((doc.collection, doc.key), []).append((ref, path, match))
    parts = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; img-src 'self'; "
        "style-src 'unsafe-inline'; script-src 'unsafe-inline'\">",
        f'<title>{_e(os.path.basename(store.bundle.rstrip(os.sep)) or "Couchbase Lite")} export</title>',
        f'<style>{_CSS}</style></head><body>',
        f'<h1>{_e(os.path.basename(store.bundle.rstrip(os.sep)) or store.db_path)}</h1>',
        f'<p class="muted">Exported by cblite-parser {_e(__version__)} on {_e(info["generated_utc"])}. '
        'Values are as decoded from the database; field names are the app\'s own and their meaning '
        'is not established by this tool.</p>',
        '<h2>Source</h2><div class="wrap"><table><thead><tr><th>file</th><th>bytes</th><th>SHA-256</th></tr></thead><tbody>',
    ]
    for src in info['source_files']:
        parts.append(f'<tr><td>{_e(src["path"])}</td><td>{src["bytes"]}</td><td><code>{_e(src["sha256"])}</code></td></tr>')
    parts.append('</tbody></table></div><h2>Database</h2><dl>')
    parts.append(f'<dt>versioning</dt><dd>{_e(store.versioning)} ({_e(info["versioning_name"])})</dd>')
    parts.append(f'<dt>shared keys</dt><dd>{_e(info["shared_keys"])}</dd>')
    for name, counts in info['collections'].items():
        parts.append(f'<dt>{_e(name)}</dt><dd>{counts["documents"]} documents, {counts["tombstones"]} tombstones</dd>')
    parts.append(f'<dt>replicator checkpoints</dt><dd>{len(store.checkpoints())}</dd></dl>')
    other = {k: v for k, v in store.info.items() if k != 'SharedKeys'}
    parts.append('<details><summary>kv_info records</summary>'
                 f'<pre>{_e(_pretty(other))}</pre></details>')
    if store.shared_keys:
        parts.append('<details><summary>shared key table</summary>'
                     f'<pre>{_e(_pretty(dict(enumerate(store.shared_keys))))}</pre></details>')

    by_collection = {}
    for doc in docs:
        by_collection.setdefault(doc.collection, []).append(doc)
    for t, (name, items) in enumerate(by_collection.items()):
        table = f'docs{t}'
        parts.append(f'<h2>Collection {_e(name)}</h2>')
        parts.append(f'<input type="search" placeholder="Filter rows, including full bodies" data-table="{table}"> '
                     f'<span class="muted" id="{table}-count">{len(items)} of {len(items)}</span>')
        parts.append(f'<div class="wrap"><table id="{table}"><thead><tr><th>sequence</th><th>key</th>'
                     '<th>revid</th><th>flags</th><th>expiration (UTC)</th><th>body</th></tr></thead><tbody>')
        for doc in items:
            flags = ' '.join(doc.flags + (['tombstone table'] if doc.tombstone_table else []))
            index = len(payload)
            payload.append(_doc_payload(doc))
            if doc.body is not None:
                preview = _compact(doc.body)
                preview = preview if len(preview) <= 160 else preview[:160] + '...'
                body = f'<details data-doc="{index}"><summary>{_e(preview)}</summary>'
            elif doc.body_error:
                body = f'<details data-doc="{index}"><summary class="bad">not decoded</summary>'
            else:
                body = f'<details data-doc="{index}"><summary>no body</summary>'
            for ref, path, match in blobs_by_doc.get((doc.collection, doc.key), []):
                state = 'file missing' if path is None and ref.digest else (
                    '' if match is None else ('SHA-1 matches' if match else 'SHA-1 DOES NOT MATCH'))
                body += f'<p>blob <code>{_e(ref.path)}</code> {_e(ref.content_type or "")} {_e(state)}</p>'
                if path in images:
                    body += f'<img class="blob" src="{_e(images[path])}" alt="blob {_e(ref.path)}">'
            body += '<div class="lazy"></div></details>'
            parts.append(f'<tr><td>{_e(doc.sequence)}</td><td><code>{_e(doc.key)}</code></td>'
                         f'<td><code>{_e(doc.revid)}</code></td><td>{_e(flags)}</td>'
                         f'<td>{_e(doc.expiration_utc.isoformat() if doc.expiration_utc else "")}</td>'
                         f'<td class="body">{body}</td></tr>')
        parts.append('</tbody></table></div>')

    parts.append('<h2>Blobs</h2>')
    if not blob_rows and not orphans:
        parts.append('<p class="muted">No document refers to a blob, and the Attachments folder holds no blob files.</p>')
    else:
        parts.append('<div class="wrap"><table><thead><tr><th>document</th><th>path</th><th>digest</th>'
                     '<th>length</th><th>type</th><th>file</th><th>SHA-1</th></tr></thead><tbody>')
        for doc, ref, path, match in blob_rows:
            state = 'file missing' if path is None and ref.digest else (
                '' if match is None else ('matches' if match else '<span class="bad">does not match</span>'))
            img = f'<img class="blob" src="{_e(images[path])}" alt="">' if path in images else ''
            parts.append(f'<tr><td><code>{_e(doc.key)}</code></td><td><code>{_e(ref.path)}</code></td>'
                         f'<td><code>{_e(ref.digest)}</code></td><td>{_e(ref.length)}</td><td>{_e(ref.content_type)}</td>'
                         f'<td>{_e(os.path.basename(path) if path else "")}{img}</td><td>{state}</td></tr>')
        for name in orphans:
            path = os.path.join(store.bundle, 'Attachments', name)
            img = f'<img class="blob" src="{_e(images[path])}" alt="">' if path in images else ''
            parts.append(f'<tr><td class="muted">no document</td><td></td><td></td><td></td><td></td>'
                         f'<td>{_e(name)}{img}</td><td>orphan</td></tr>')
        parts.append('</tbody></table></div>')
    parts.append(f'<script type="application/json" id="docdata">{_script_json(payload)}</script>')
    parts.append(f'<script>{_JS}</script></body></html>')
    with open(os.path.join(out_dir, 'index.html'), 'w', encoding='utf-8') as handle:
        handle.write('\n'.join(parts))
