"""Command line entry point: ``python -m cblite_parser <command> <store>``.

``<store>`` is a ``.cblite2`` directory or its ``db.sqlite3``. The database is read from a
temporary copy, never in place.

``info``      the database's own records: document versioning, UUIDs, shared key count,
              replication remotes, and each collection with its live and tombstone counts.
``dump``      one JSON object per document, one per line, in sequence order within each
              collection. ``--revisions`` adds the revision tree, which keeps the IDs of earlier
              revisions and sometimes their bodies.
``blobs``     one tab-separated line per blob reference: the document, the property path, the
              digest, the recorded length and content type, the blob file, and whether the
              file's SHA-1 matches the digest. Files no document names follow, marked orphan.
``fleece``    decode a raw Fleece file; ``--shared-keys-from`` maps integer keys through a
              database's SharedKeys.

Binary values print as ``{"$base64": ...}`` and non-finite floats as ``{"$float": "nan"}`` so
every line stays strict JSON.
"""
import argparse
import base64
import json
import math
import os
import sys

from . import CBLiteError, FleeceError, Store, VERSIONING, decode_fleece


def _jsonable(value):
    if isinstance(value, bytes):
        return {'$base64': base64.b64encode(value).decode('ascii')}
    if isinstance(value, float) and not math.isfinite(value):
        return {'$float': repr(value)}
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    if value is not None and not isinstance(value, (str, int, float, bool)):
        return repr(value)
    return value


def _line(obj, out):
    print(json.dumps(_jsonable(obj), ensure_ascii=False, allow_nan=False), file=out)


def info(store, out=sys.stdout):
    data = {
        'database': store.db_path,
        'wal_present': store.wal_present,
        'versioning': store.versioning,
        'versioning_name': VERSIONING.get(store.versioning),
        'shared_keys': len(store.shared_keys) if store.shared_keys is not None else None,
        'info': {k: v for k, v in store.info.items() if k != 'SharedKeys'},
        'collections': {},
        'checkpoints': len(store.checkpoints()),
    }
    for name in store.collections():
        live = tombstones = 0
        for doc in store.documents(collection=name):
            if doc.tombstone_table:
                tombstones += 1
            else:
                live += 1
        data['collections'][name] = {'documents': live, 'tombstones': tombstones}
    print(json.dumps(_jsonable(data), indent=2, ensure_ascii=False, allow_nan=False), file=out)


def dump(store, collection=None, revisions=False, no_tombstones=False, out=sys.stdout):
    for doc in store.documents(collection=collection, include_tombstones=not no_tombstones):
        row = {
            'collection': doc.collection, 'key': doc.key, 'sequence': doc.sequence,
            'revid': doc.revid, 'flags': doc.flags, 'deleted': doc.deleted,
            'tombstone_table': doc.tombstone_table,
            'expiration_utc': doc.expiration_utc.isoformat() if doc.expiration_utc else None,
            'body': doc.body,
        }
        if doc.body_error:
            row['body_error'] = doc.body_error
        if doc.extra_note:
            row['extra_note'] = doc.extra_note
        if revisions:
            row['revisions'] = [
                {'index': r.index, 'revid': r.revid, 'parent': r.parent, 'flags': r.flags,
                 'sequence': r.sequence, 'has_body': r.has_body,
                 **({'body': r.body} if r.has_body and r.index else {}),
                 **({'body_error': r.body_error} if r.body_error else {})}
                for r in doc.revisions]
            row['remote_revisions'] = doc.remote_revisions
        _line(row, out)


def blobs(store, out=sys.stdout):
    print('collection\tdocument\tpath\tdigest\tlength\tcontent_type\tfile\tsha1_matches', file=out)
    for doc, ref, path, match in store.blobs():
        state = '' if match is None else ('yes' if match else 'no')
        if path is None and ref.digest:
            state = 'file missing'
        if ref.inline_bytes is not None:
            state = f'inline, {ref.inline_bytes} bytes'
        print('\t'.join(str(x) for x in (
            doc.collection, doc.key, ref.path, ref.digest or '', '' if ref.length is None else ref.length,
            ref.content_type or '', path or '', state)), file=out)
    for name in store.orphan_blob_files():
        print('\t'.join(('', '', '', '', '', '', os.path.join(store.bundle, 'Attachments', name), 'orphan')),
              file=out)


def main(argv=None):
    """Parse arguments and run; returns the process exit status."""
    parser = argparse.ArgumentParser(
        prog='python -m cblite_parser',
        description='Read a Couchbase Lite database or a Fleece document without the app that wrote it.')
    commands = parser.add_subparsers(dest='command', required=True)
    for name, text in (('info', "print the database's own records and a per-collection count"),
                       ('dump', 'print every document as one JSON object per line'),
                       ('blobs', 'print every blob reference and whether its file matches')):
        sub = commands.add_parser(name, help=text)
        sub.add_argument('store', help='the .cblite2 directory or its db.sqlite3')
        if name == 'dump':
            sub.add_argument('--collection', help='only this collection, as scope.name')
            sub.add_argument('--revisions', action='store_true',
                             help='add the revision tree: earlier revision IDs and any retained bodies')
            sub.add_argument('--no-tombstones', action='store_true',
                             help='leave out the rows of the kv_del_ tombstone tables')
    fl = commands.add_parser('fleece', help='decode a raw Fleece file')
    fl.add_argument('file')
    fl.add_argument('--shared-keys-from', metavar='STORE',
                    help='map integer keys through the SharedKeys of this database')
    args = parser.parse_args(argv)

    try:
        if args.command == 'fleece':
            shared = None
            if args.shared_keys_from:
                with Store(args.shared_keys_from) as store:
                    shared = store.shared_keys
            with open(args.file, 'rb') as handle:
                _line(decode_fleece(handle.read(), shared), sys.stdout)
        else:
            with Store(args.store) as store:
                if args.command == 'info':
                    info(store)
                elif args.command == 'dump':
                    dump(store, args.collection, args.revisions, args.no_tombstones)
                else:
                    blobs(store)
        sys.stdout.flush()
    except (CBLiteError, FleeceError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
    except OSError as exc:
        print(f'error: {exc.strerror or exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
