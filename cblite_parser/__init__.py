"""Read-only reader for Couchbase Lite (LiteCore) databases and Fleece documents.

A Couchbase Lite database is a ``<name>.cblite2`` directory holding ``db.sqlite3`` (with its
``-wal`` and ``-shm``) and an ``Attachments`` directory of blob files. Document bodies are
Fleece, Couchbase's binary JSON-like encoding, and their dictionary keys are usually small
integers that index a table of key names the database keeps once, in ``kv_info`` under the
key ``SharedKeys``.

The format facts below come from the published source, pinned to two commits:

* couchbase/fleece 8ce5f690480b77c0f93d03f456a29828b5a55d66 (``Fleece.md``,
  ``Fleece/Core/Value.cc``, ``Fleece/Core/Array.cc``, ``Fleece/Core/Pointer.hh``)
* couchbase/couchbase-lite-core 3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f (``LiteCore/Storage``,
  ``LiteCore/RevTrees``, ``LiteCore/Database``, ``C/c4BlobStore.cc``)

This is an independent implementation written from those sources; no Couchbase code is
included. The database is never opened in place: ``Store`` copies ``db.sqlite3`` and its
sidecars to a temporary directory and reads the copy, because a read-only SQLite open with a
``-wal`` beside it still writes the ``-shm``.
"""
import base64
import dataclasses
import datetime
import hashlib
import os
import re
import shutil
import sqlite3
import struct
import tempfile
import typing

__all__ = [
    'CBLiteError', 'FleeceError', 'Store', 'Document', 'Revision', 'BlobRef',
    'decode_fleece', 'decode_rev_tree', 'format_revid', 'iter_blob_refs',
]
__version__ = '1.1.0'


class CBLiteError(Exception):
    """The database cannot be read as a Couchbase Lite store."""


class FleeceError(ValueError):
    """The bytes cannot be read as Fleece."""


# ---------------------------------------------------------------------------
# Fleece
# ---------------------------------------------------------------------------

UNDEFINED = type('Undefined', (), {'__repr__': lambda self: 'undefined'})()
"""Fleece's ``undefined`` special value. Inside a dict it marks a deleted key and is
dropped; it is returned only when it is the root or an array item."""


def _uvarint(buf, pos):
    result = shift = 0
    for i in range(10):
        if pos + i >= len(buf):
            raise FleeceError('varint runs past the end of the data')
        byte = buf[pos + i]
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            return result, i + 1
        shift += 7
    raise FleeceError('varint is too long')


def _deref(buf, pos, wide):
    # Pointer.hh: the offset is in 2-byte units, always backwards; bit 0x40 of the first
    # byte marks an "extern" pointer into a separate base document.
    if wide:
        if pos + 4 > len(buf):
            raise FleeceError('wide pointer runs past the end of the data')
        raw = struct.unpack_from('>I', buf, pos)[0]
        external, offset = raw & 0x40000000, (raw & 0x3FFFFFFF) << 1
    else:
        raw = struct.unpack_from('>H', buf, pos)[0]
        external, offset = raw & 0x4000, (raw & 0x3FFF) << 1
    if external:
        # Pointer.cc derefExtern / carefulDeref: with no base document to resolve against, a
        # narrow pointer is read as a legacy pointer from before the extern flag existed, whose
        # offset is fifteen bits, and kept only if it lands inside the data. A wide one is refused.
        legacy = (raw & 0x7FFF) << 1
        if wide or legacy == 0 or legacy > pos:
            raise FleeceError('extern pointer into a base document this reader does not have')
        return pos - legacy
    if offset == 0 or offset > pos:
        raise FleeceError(f'pointer at {pos} has an invalid offset {offset}')
    return pos - offset


def _slot(buf, pos, wide, shared_keys, depth):
    if pos + 2 > len(buf):
        raise FleeceError('collection slot runs past the end of the data')
    if buf[pos] & 0x80:
        pos = _deref(buf, pos, wide)
    return _value(buf, pos, shared_keys, depth + 1)


def _value(buf, pos, shared_keys, depth):
    if depth > 200:
        raise FleeceError('values are nested too deeply')
    if pos + 2 > len(buf):
        raise FleeceError('value runs past the end of the data')
    b0, b1 = buf[pos], buf[pos + 1]
    tag = b0 >> 4
    if tag == 0:                                    # small int, 12-bit signed
        small = ((b0 & 0x0F) << 8) | b1
        return small - 0x1000 if small & 0x800 else small
    if tag == 1:                                    # int: low 3 bits = size - 1, bit 3 = unsigned
        size = (b0 & 0x07) + 1
        data = buf[pos + 1:pos + 1 + size]
        if len(data) != size:
            raise FleeceError('integer runs past the end of the data')
        return int.from_bytes(data, 'little', signed=not b0 & 0x08)
    if tag == 2:                                    # float: bit 3 = 64-bit; data at +2
        fmt, size = ('<d', 8) if b0 & 0x08 else ('<f', 4)
        if pos + 2 + size > len(buf):
            raise FleeceError('float runs past the end of the data')
        return struct.unpack_from(fmt, buf, pos + 2)[0]
    if tag == 3:                                    # special
        return {0x00: None, 0x04: False, 0x08: True, 0x0C: UNDEFINED}[b0 & 0x0C]
    if tag in (4, 5):                               # string / binary
        size, start = b0 & 0x0F, pos + 1
        if size == 0x0F:
            size, used = _uvarint(buf, start)
            start += used
        data = buf[start:start + size]
        if len(data) != size:
            raise FleeceError('string runs past the end of the data')
        return data.decode('utf-8', 'surrogateescape') if tag == 4 else bytes(data)
    if tag in (6, 7):                               # array / dict
        wide = bool(b0 & 0x08)
        width = 4 if wide else 2
        count = ((b0 & 0x07) << 8) | b1
        first = pos + 2
        if count == 0x7FF:
            # Array.cc: a long count is 2047 plus a varint, padded to an even length
            extra, used = _uvarint(buf, first)
            count += extra
            first += used + (used & 1)
        if tag == 6:
            return [_slot(buf, first + i * width, wide, shared_keys, depth) for i in range(count)]
        result = {}
        for i in range(count):
            key_pos = first + 2 * i * width
            key = _slot(buf, key_pos, wide, None, depth)
            value = _slot(buf, key_pos + width, wide, shared_keys, depth)
            if key == -2048:
                # Fleece.md, dictionary inheritance: the value is the parent dict, and the
                # keys after this one override it
                if isinstance(value, dict):
                    result.update(value)
                continue
            if isinstance(key, int) and shared_keys is not None and 0 <= key < len(shared_keys):
                key = shared_keys[key]
            if value is UNDEFINED:
                result.pop(key, None)
            else:
                result[key] = value
        return result
    raise FleeceError(f'unexpected pointer at offset {pos}')


def decode_fleece(data, shared_keys=None):
    """Return the root value of a Fleece document.

    ``shared_keys`` is the list of key names that integer dict keys index; without it those
    keys come back as ints. Raises ``FleeceError`` on anything that cannot be read.
    """
    buf = bytes(data)
    if len(buf) < 2 or len(buf) % 2:
        raise FleeceError(f'length {len(buf)} is not a positive even number')
    # Fleece.md "Finding the root": the last two bytes, dereferenced as a narrow pointer,
    # then once more as a wide pointer when the target is itself a pointer
    pos = len(buf) - 2
    if buf[pos] & 0x80:
        pos = _deref(buf, pos, False)
        if buf[pos] & 0x80:
            pos = _deref(buf, pos, True)
    return _value(buf, pos, shared_keys, 0)


# ---------------------------------------------------------------------------
# Revision trees and revision IDs
# ---------------------------------------------------------------------------

REV_FLAGS = {  # RevTree.hh Rev::Flags; 0x80 on disk is RawRevision::kHasData
    0x01: 'deleted', 0x02: 'leaf', 0x04: 'new', 0x08: 'hasAttachments',
    0x10: 'keepBody', 0x20: 'isConflict', 0x40: 'closed',
}
DOC_FLAGS = {  # Record.hh DocumentFlags
    0x01: 'deleted', 0x02: 'conflicted', 0x04: 'hasAttachments', 0x08: 'synced', 0x80: 'rejected',
}


def _flag_names(value, table):
    names = [name for bit, name in table.items() if value & bit]
    unknown = value & ~sum(table)
    if unknown:
        names.append(f'0x{unknown:x}')
    return names


def format_revid(raw):
    """Render a stored revision ID the way LiteCore prints it.

    A tree revision ID is a varint generation followed by the digest, printed as
    ``<generation>-<hex digest>``. One whose first byte is zero is a version vector, which this
    reader does not decode; it is returned as ``v:<hex>`` as stored.
    """
    if raw is None:
        return None
    raw = bytes(raw)
    if not raw:
        return ''
    if raw[0] == 0:
        return 'v:' + raw.hex()
    try:
        generation, used = _uvarint(raw, 0)
    except FleeceError:
        return 'raw:' + raw.hex()
    return f'{generation}-{raw[used:].hex()}'


@dataclasses.dataclass
class Revision:
    """One revision of a revision tree, in the order LiteCore stored them."""
    index: int
    revid: str
    parent: typing.Optional[int]
    flags: typing.List[str]
    sequence: int
    body: typing.Any = None
    has_body: bool = False
    body_error: typing.Optional[str] = None


def is_rev_tree(data):
    """True when ``data`` frames as a LiteCore RawRevTree (RawRevTree.cc isRevTree)."""
    buf = bytes(data or b'')
    if len(buf) < 9:
        return False
    pos = 0
    while pos + 4 <= len(buf):
        size = struct.unpack_from('>I', buf, pos)[0]
        if size == 0:
            return pos != 0
        if pos + 8 > len(buf):
            return False
        rev_id_len = buf[pos + 7]
        if size <= 8 + rev_id_len or pos + size > len(buf):
            return False
        pos += size
    return False


def decode_rev_tree(data, shared_keys=None, current_body=None, current_sequence=None):
    """Decode a RawRevTree into ``(revisions, remote_map)``.

    Each revision is header ``size u32 BE, parent u16 BE, flags u8, revIDLen u8``, the revID,
    a varint sequence, then the body when flag 0x80 is set. A zero size ends the list; then come
    ``(remote id u16 BE, revision index u16 BE)`` pairs naming the revision each remote database
    last had, up to a 0/0 mark. ``current_body`` is decoded for the first revision when it
    carries no body of its own, which is how a 3.x record keeps the current body in ``body``
    and the tree in ``extra``. A revision stored with sequence 0 takes ``current_sequence``,
    as RawRevTree.cc decodeTree does with the record's own sequence.
    """
    buf = bytes(data)
    revisions, pos = [], 0
    while True:
        if pos + 4 > len(buf):
            raise FleeceError('revision tree runs past the end of the data')
        size = struct.unpack_from('>I', buf, pos)[0]
        if size == 0:
            pos += 4
            break
        if size < 8 or pos + size > len(buf):
            raise FleeceError(f'revision at {pos} has a size {size} that does not fit')
        parent, flags, rev_id_len = struct.unpack_from('>HBB', buf, pos + 4)
        rev_id = buf[pos + 8:pos + 8 + rev_id_len]
        sequence, used = _uvarint(buf, pos + 8 + rev_id_len)
        if sequence == 0 and current_sequence is not None:
            sequence = current_sequence
        body_bytes = buf[pos + 8 + rev_id_len + used:pos + size] if flags & 0x80 else None
        rev = Revision(index=len(revisions), revid=format_revid(rev_id),
                       parent=None if parent == 0xFFFF else parent,
                       flags=_flag_names(flags & 0x7F, REV_FLAGS), sequence=sequence)
        source = body_bytes if body_bytes is not None else (current_body if not revisions else None)
        if source:
            rev.has_body = True
            try:
                rev.body = decode_fleece(source, shared_keys)
            except FleeceError as exc:
                rev.body_error = str(exc)
        revisions.append(rev)
        pos += size
    remote_map = {}
    while pos + 4 <= len(buf):
        remote_id, rev_index = struct.unpack_from('>HH', buf, pos)
        pos += 4
        if remote_id == 0 and rev_index == 0:
            break
        remote_map[remote_id] = rev_index
    return revisions, remote_map


# ---------------------------------------------------------------------------
# Blobs
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class BlobRef:
    """A blob a document refers to (c4BlobStore.hh: ``{"@type": "blob", "digest": ...}`` or an
    entry of the legacy ``_attachments`` dict)."""
    path: str
    digest: typing.Optional[str]
    length: typing.Any
    content_type: typing.Any
    inline_bytes: typing.Optional[int]
    legacy: bool


def iter_blob_refs(body, _path='$'):
    """Yield every blob reference inside a decoded document body."""
    if isinstance(body, dict):
        legacy = body.get('_attachments')
        if isinstance(legacy, dict):
            for name, att in legacy.items():
                if isinstance(att, dict):
                    yield _blob_ref(att, f'{_path}._attachments.{name}', True)
        if body.get('@type') == 'blob':
            yield _blob_ref(body, _path, False)
        for key, value in body.items():
            if key != '_attachments':
                yield from iter_blob_refs(value, f'{_path}.{key}')
    elif isinstance(body, list):
        for i, value in enumerate(body):
            yield from iter_blob_refs(value, f'{_path}[{i}]')


def _blob_ref(d, path, legacy):
    data = d.get('data')
    return BlobRef(path=path, digest=d.get('digest') if isinstance(d.get('digest'), str) else None,
                   length=d.get('length'), content_type=d.get('content_type'),
                   inline_bytes=len(data) if isinstance(data, (bytes, str)) else None, legacy=legacy)


def blob_filename(digest):
    """The file name LiteCore gives a blob: its SHA-1 digest in base64 with '/' turned into '_',
    plus ``.blob`` (c4BlobStore.cc BlobKeyToFilename). None for a digest it cannot hold."""
    if not isinstance(digest, str) or not digest.startswith('sha1-'):
        return None
    try:
        raw = base64.b64decode(digest[5:], validate=True)
    except (ValueError, base64.binascii.Error):
        return None
    if len(raw) != 20:
        return None
    return base64.b64encode(raw).decode('ascii').replace('/', '_') + '.blob'


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

VERSIONING = {0: 'revision trees, 2.x schema', 1: 'revision trees, 3.x schema', 2: 'version vectors'}
_TABLE_RE = re.compile(r'^kv_(del_)?(default|\..+)$')


@dataclasses.dataclass
class Document:
    """One row of a document table."""
    collection: str
    key: str
    sequence: typing.Optional[int]
    flags: typing.List[str]
    subsequence: int
    revid: typing.Optional[str]
    tombstone_table: bool
    expiration: typing.Optional[int]
    body: typing.Any = None
    body_error: typing.Optional[str] = None
    revisions: typing.List[Revision] = dataclasses.field(default_factory=list)
    remote_revisions: typing.Dict[int, int] = dataclasses.field(default_factory=dict)
    extra_bytes: int = 0
    extra_note: typing.Optional[str] = None

    @property
    def deleted(self):
        return self.tombstone_table or 'deleted' in self.flags

    @property
    def expiration_utc(self):
        """Expiration as a UTC datetime; LiteCore stores milliseconds since the Unix epoch
        (KeyStore.cc ``KeyStore::now``)."""
        if not self.expiration:
            return None
        return datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(
            milliseconds=self.expiration)


def collection_name(table):
    """``kv_default`` -> ``_default._default``; ``kv_.name`` -> ``_default.name``;
    ``kv_.scope.name`` -> ``scope.name``. Backslashes, LiteCore's escape for capital letters,
    are removed (SQLiteKeyStore.cc transformCollectionName; DatabaseImpl.cc
    keyStoreNameToCollectionSpec)."""
    match = _TABLE_RE.match(table)
    if not match:
        return None
    name = match.group(2).replace('\\', '')
    if name == 'default':
        return '_default._default'
    name = name[1:]
    return name if '.' in name else f'_default.{name}'


class Store:
    """A Couchbase Lite database, read from a temporary copy.

    ``path`` is the ``.cblite2`` directory or its ``db.sqlite3``. Use as a context manager, or
    call ``close()``, so the copy is removed.
    """

    def __init__(self, path):
        path = os.fspath(path)
        if os.path.isdir(path):
            self.bundle = path
            db_path = os.path.join(path, 'db.sqlite3')
        else:
            db_path = path
            self.bundle = os.path.dirname(path)
        if not os.path.isfile(db_path):
            raise CBLiteError(f'{db_path} not found')
        self.db_path = db_path
        self._tmp = tempfile.mkdtemp(prefix='cblite-parser-')
        try:
            copy = os.path.join(self._tmp, 'db.sqlite3')
            shutil.copyfile(db_path, copy)
            for suffix in ('-wal', '-shm'):
                if os.path.isfile(db_path + suffix):
                    shutil.copyfile(db_path + suffix, copy + suffix)
            self.wal_present = os.path.isfile(db_path + '-wal')
            self._con = sqlite3.connect(f'file:{copy}?mode=ro', uri=True)
            self._con.text_factory = lambda b: b.decode('utf-8', 'surrogateescape')
            tables = {r[0] for r in self._con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        except sqlite3.DatabaseError as exc:
            self.close()
            raise CBLiteError(f'{db_path} is not a readable SQLite database ({exc}); an '
                              'Enterprise Edition database can be encrypted') from exc
        except OSError:
            self.close()
            raise
        if 'kv_info' not in tables and not any(_TABLE_RE.match(t) for t in tables):
            self.close()
            raise CBLiteError(f'{db_path} has no LiteCore key-store tables')
        self.tables = tables
        self.info = self._read_info()
        self.shared_keys = self.info.get('SharedKeys') if isinstance(self.info.get('SharedKeys'), list) else None
        self.versioning = self.info.get('versioning')

    def close(self):
        con = getattr(self, '_con', None)
        if con is not None:
            con.close()
            self._con = None
        if getattr(self, '_tmp', None):
            shutil.rmtree(self._tmp, ignore_errors=True)
            self._tmp = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _read_info(self):
        """kv_info, each value read the way LiteCore writes it (DatabaseImpl.cc, DataFile.cc,
        Record.cc, CookieStore.cc); a key not listed here is returned as raw bytes."""
        info = {}
        if 'kv_info' not in self.tables:
            return info
        for key, body in self._con.execute('SELECT key, body FROM kv_info'):
            body = bytes(body) if body is not None else b''
            if key in ('SharedKeys', 'remotes', 'org.couchbase.cookies'):
                try:
                    info[key] = decode_fleece(body)
                except FleeceError as exc:
                    info[key] = {'$error': str(exc), '$bytes': body}
            elif key in ('versioning', 'maxRowidWithDeletedInDefault'):
                # Record::bodyAsUInt: eight bytes, big-endian
                info[key] = int.from_bytes(body[:8], 'big') if len(body) >= 8 else None
            elif key.endswith('UUID') and len(body) == 16:
                info[key] = body.hex()
            else:
                info[key] = body
        return info

    def collections(self):
        """Collection names with their live and tombstone tables, in table order."""
        found = {}
        for table in sorted(self.tables):
            name = collection_name(table)
            if name:
                found.setdefault(name, []).append(table)
        return found

    def checkpoints(self):
        """Rows of kv_checkpoints, the replicator's saved positions, as (key, body bytes)."""
        if 'kv_checkpoints' not in self.tables:
            return []
        return [(k, bytes(b or b'')) for k, b in self._con.execute('SELECT key, body FROM kv_checkpoints')]

    def documents(self, collection=None, include_tombstones=True):
        """Yield every ``Document`` of every collection (or one), live tables first."""
        for name, tables in self.collections().items():
            if collection and name != collection:
                continue
            for table in sorted(tables, key=lambda t: t.startswith('kv_del_')):
                tombstones = table.startswith('kv_del_')
                if tombstones and not include_tombstones:
                    continue
                yield from self._read_table(name, table, tombstones)

    def _read_table(self, name, table, tombstones):
        columns = [r[1] for r in self._con.execute(f'PRAGMA table_info("{table}")')]
        wanted = [c for c in ('key', 'sequence', 'flags', 'version', 'body', 'extra', 'expiration') if c in columns]
        sql = f'SELECT {", ".join(wanted)} FROM "{table}" ORDER BY sequence'
        for row in self._con.execute(sql):
            r = dict(zip(wanted, row))
            raw_flags = r.get('flags') or 0
            doc = Document(collection=name, key=r['key'], sequence=r.get('sequence'),
                           flags=_flag_names(raw_flags & 0xFFFF, DOC_FLAGS), subsequence=raw_flags >> 16,
                           revid=format_revid(r.get('version')), tombstone_table=tombstones,
                           expiration=r.get('expiration'))
            body = bytes(r['body']) if r.get('body') is not None else b''
            extra = bytes(r['extra']) if r.get('extra') is not None else b''
            doc.extra_bytes = len(extra)
            self._decode_record(doc, body, extra, bytes(r['version']) if r.get('version') else b'')
            yield doc

    def _decode_record(self, doc, body, extra, version):
        """Decide where the revision tree lives the way VectorRecord.cc does: in ``extra`` when
        there is one, unless the version is a version vector or ``extra`` starts with four zero
        bytes (the 4.x format); with no ``extra``, in ``body`` when it frames as a RawRevTree
        (a 2.x record, or one a 3.x database has not yet re-saved)."""
        sk = self.shared_keys
        is_vector = bool(version) and version[0] == 0
        if extra:
            tree_in_extra = not is_vector and extra[:4] != b'\x00\x00\x00\x00'
            tree_in_body = False
        else:
            tree_in_extra = False
            tree_in_body = bool(body) and not is_vector and is_rev_tree(body)
        if tree_in_body:
            try:
                doc.revisions, doc.remote_revisions = decode_rev_tree(body, sk, current_sequence=doc.sequence)
                if doc.revisions:
                    doc.body, doc.body_error = doc.revisions[0].body, doc.revisions[0].body_error
            except FleeceError as exc:
                doc.body_error = f'revision tree: {exc}'
        elif body:
            try:
                doc.body = decode_fleece(body, sk)
            except FleeceError as exc:
                doc.body_error = str(exc)
        if tree_in_extra:
            try:
                doc.revisions, doc.remote_revisions = decode_rev_tree(extra, sk, current_body=body,
                                                                       current_sequence=doc.sequence)
            except FleeceError as exc:
                doc.extra_note = f'revision tree not read: {exc}'
        elif extra:
            # version-vector records keep remote revisions in `extra` as Fleece that may point
            # back into `body`; that layout is not decoded here
            doc.extra_note = 'version-vector revisions, not decoded'

    def blobs(self):
        """Yield ``(document, BlobRef, file path or None, sha1 matches or None)`` for every blob
        reference in every current body and retained revision body."""
        attachments = os.path.join(self.bundle, 'Attachments')
        for doc in self.documents():
            bodies = [doc.body] + [r.body for r in doc.revisions[1:] if r.has_body]
            seen = set()
            for body in bodies:
                for ref in iter_blob_refs(body):
                    marker = (ref.path, ref.digest)
                    if marker in seen:
                        continue
                    seen.add(marker)
                    name = blob_filename(ref.digest)
                    path = os.path.join(attachments, name) if name else None
                    if path and not os.path.isfile(path):
                        yield doc, ref, None, None
                        continue
                    match = None
                    if path:
                        digest = hashlib.sha1()
                        with open(path, 'rb') as handle:
                            for chunk in iter(lambda: handle.read(1 << 20), b''):
                                digest.update(chunk)
                        match = 'sha1-' + base64.b64encode(digest.digest()).decode('ascii') == ref.digest
                    yield doc, ref, path, match

    def orphan_blob_files(self):
        """Files in Attachments/ that no current or retained revision body names."""
        attachments = os.path.join(self.bundle, 'Attachments')
        if not os.path.isdir(attachments):
            return []
        named = {os.path.basename(p) for _d, _r, p, _m in self.blobs() if p}
        return sorted(f for f in os.listdir(attachments)
                      if f.endswith('.blob') and f not in named)
