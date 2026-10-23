"""Hand-built fixtures for the tests: a small Fleece writer, a RawRevTree writer, and a
LiteCore-shaped SQLite database. Written from the same sources the reader cites, so the
known-answer tests in test_fleece.py also pin bytes copied from Fleece.md itself, which this
writer did not produce.
"""
import os
import sqlite3
import struct


class FleeceWriter:
    """Writes values bottom-up, the way Fleece.md describes the encoder: a collection's
    out-of-line values first, then the collection, then a trailing pointer to the root."""

    def __init__(self):
        self.buf = bytearray()

    def _pad(self):
        if len(self.buf) % 2:
            self.buf.append(0)

    def _put(self, data):
        self._pad()
        pos = len(self.buf)
        self.buf += data
        self._pad()
        return pos

    @staticmethod
    def _inline(value):
        """Two-byte form of a value that fits in a slot, or None."""
        if value is DELETE:
            return b'\x3c\x00'
        if value is None:
            return b'\x30\x00'
        if value is False:
            return b'\x34\x00'
        if value is True:
            return b'\x38\x00'
        if isinstance(value, int) and -2048 <= value <= 2047:
            v = value & 0xFFF
            return bytes([(v >> 8) & 0x0F, v & 0xFF])
        if isinstance(value, str) and len(value.encode()) <= 1:
            data = value.encode()
            return bytes([0x40 | len(data)]) + (data or b'\x00')
        return None

    def _scalar(self, value):
        if isinstance(value, bool) or value is None:
            raise AssertionError('inline only')
        if isinstance(value, int):
            for size in range(1, 9):
                try:
                    data = value.to_bytes(size, 'little', signed=True)
                    return self._put(bytes([0x10 | (size - 1)]) + data)
                except OverflowError:
                    continue
            data = value.to_bytes(8, 'little', signed=False)
            return self._put(bytes([0x18 | 7]) + data)
        if isinstance(value, float):
            return self._put(b'\x28\x00' + struct.pack('<d', value))
        if isinstance(value, (str, bytes)):
            data = value.encode() if isinstance(value, str) else value
            tag = 0x40 if isinstance(value, str) else 0x50
            if len(data) < 15:
                return self._put(bytes([tag | len(data)]) + data)
            n, var = len(data), bytearray()
            while True:
                b = n & 0x7F
                n >>= 7
                var.append(b | 0x80 if n else b)
                if not n:
                    break
            return self._put(bytes([tag | 0x0F]) + bytes(var) + data)
        raise TypeError(type(value))

    def _write(self, value, wide=False):
        """Return ('inline', bytes) or ('at', offset)."""
        if isinstance(value, (list, dict)):
            return 'at', self._collection(value, wide)
        inline = self._inline(value)
        if inline is not None:
            return 'inline', inline
        return 'at', self._scalar(value)

    def _slot_bytes(self, kind, data, slot_pos, width):
        if kind == 'inline':
            return data + b'\x00' * (width - 2)
        offset = (slot_pos - data) // 2
        if width == 2:
            assert 0 < offset < 0x4000, offset
            return struct.pack('>H', 0x8000 | offset)
        return struct.pack('>I', 0x80000000 | offset)

    def _collection(self, value, wide=False, inherit=None):
        width = 4 if wide else 2
        if isinstance(value, dict):
            def sort_key(k):
                return (0, k) if isinstance(k, int) else (1, k.encode())
            items = []
            if inherit is not None:
                items.append((-2048, inherit))
            items += sorted(value.items(), key=lambda kv: sort_key(kv[0]))
            entries = []
            for k, v in items:
                if k == -2048:
                    # Fleece.md dictionary inheritance: key -2048, value a pointer to the parent
                    entries.append((('inline', self._inline(-2048)), ('at', inherit)))
                else:
                    entries.append((self._write(k), self._write(v, wide)))
            slots = [s for pair in entries for s in pair]
            tag, count = 0x70, len(entries)
        else:
            slots = [self._write(v, wide) for v in value]
            tag, count = 0x60, len(value)
        self._pad()
        start = len(self.buf)
        if count < 0x7FF:
            header = bytes([tag | (0x08 if wide else 0) | (count >> 8), count & 0xFF])
        else:
            extra, var = count - 0x7FF, bytearray()
            while True:
                b = extra & 0x7F
                extra >>= 7
                var.append(b | 0x80 if extra else b)
                if not extra:
                    break
            if len(var) % 2:
                var.append(0)
            header = bytes([tag | (0x08 if wide else 0) | 0x07, 0xFF]) + bytes(var)
        self.buf += header
        for kind, data in slots:
            self.buf += self._slot_bytes(kind, data, len(self.buf), width)
        return start

    def finish(self, root, wide=False):
        kind, data = self._write(root, wide)
        if kind == 'inline':
            if self.buf:
                raise AssertionError('inline root must be the whole document')
            return bytes(data)
        self._pad()
        self.buf += self._slot_bytes('at', data, len(self.buf), 2)
        return bytes(self.buf)


def fleece(value, shared_keys=None, wide=False):
    """Encode ``value``; string dict keys found in ``shared_keys`` are written as their index."""
    def mapped(v):
        if isinstance(v, dict):
            return {(shared_keys.index(k) if shared_keys and k in shared_keys else k): mapped(x)
                    for k, x in v.items()}
        if isinstance(v, list):
            return [mapped(x) for x in v]
        return v
    return FleeceWriter().finish(mapped(value), wide)


def fleece_inherited(parent, child_overrides):
    """A dict that inherits from ``parent`` and overrides or deletes keys; a value of
    ``DELETE`` writes Fleece ``undefined`` (0x3C), the deletion marker."""
    writer = FleeceWriter()
    parent_at = writer._collection(parent)
    writer._inline_override = True
    entries = {}
    for k, v in child_overrides.items():
        entries[k] = v
    child_at = writer._collection(entries, inherit=parent_at)
    writer._pad()
    writer.buf += writer._slot_bytes('at', child_at, len(writer.buf), 2)
    return bytes(writer.buf)


DELETE = object()


def rev_tree(revs, remotes=None):
    """RawRevTree bytes. ``revs`` holds (revid bytes, parent index or None, flags, sequence,
    body bytes or None); bodies set flag 0x80."""
    out = bytearray()
    for rev_id, parent, flags, sequence, body in revs:
        seq, n = bytearray(), sequence
        while True:
            b = n & 0x7F
            n >>= 7
            seq.append(b | 0x80 if n else b)
            if not n:
                break
        payload = bytes(rev_id) + bytes(seq) + (body or b'')
        size = 8 + len(payload)
        out += struct.pack('>IHBB', size, 0xFFFF if parent is None else parent,
                           flags | (0x80 if body is not None else 0), len(rev_id)) + payload
    out += b'\x00\x00\x00\x00'
    for remote_id, index in (remotes or {}).items():
        out += struct.pack('>HH', remote_id, index)
    if remotes:
        out += b'\x00\x00\x00\x00'
    return bytes(out)


def revid(generation, digest_hex):
    gen, n = bytearray(), generation
    while True:
        b = n & 0x7F
        n >>= 7
        gen.append(b | 0x80 if n else b)
        if not n:
            break
    return bytes(gen) + bytes.fromhex(digest_hex)


def make_store(directory, docs_by_table, info=None, v2=False, wal_rows=None):
    """Create ``directory``/db.sqlite3 with LiteCore's table shapes (SQLiteKeyStore.cc
    createTable). ``docs_by_table`` maps a table name to rows of
    (key, sequence, flags, version, body, extra, expiration). ``wal_rows`` are inserted after
    switching to WAL and left uncheckpointed, with the connection returned open so the -wal
    stays on disk."""
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, 'db.sqlite3')
    con = sqlite3.connect(path)
    con.execute('CREATE TABLE kvmeta (name TEXT PRIMARY KEY, lastSeq INTEGER DEFAULT 0, '
                'purgeCnt INTEGER DEFAULT 0) WITHOUT ROWID')
    con.execute('CREATE TABLE "kv_info" (key TEXT PRIMARY KEY, sequence INTEGER, flags INTEGER DEFAULT 0, '
                'version BLOB, body BLOB' + ('' if v2 else ', extra BLOB') + ')')
    for key, body in (info or {}).items():
        con.execute('INSERT INTO kv_info (key, body) VALUES (?, ?)', (key, body))
    for table, rows in docs_by_table.items():
        cols = 'key TEXT PRIMARY KEY, sequence INTEGER, flags INTEGER DEFAULT 0, version BLOB, body BLOB'
        if not v2:
            cols += ', extra BLOB, expiration INTEGER'
        con.execute(f'CREATE TABLE "{table}" ({cols})')
        for row in rows:
            insert(con, table, row, v2)
    con.commit()
    if wal_rows is None:
        con.close()
        return path, None
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('PRAGMA wal_autocheckpoint=0')
    for table, row in wal_rows:
        insert(con, table, row, v2)
    con.commit()
    return path, con


def insert(con, table, row, v2=False):
    key, sequence, flags, version, body, extra, expiration = row
    if v2:
        con.execute(f'INSERT INTO "{table}" (key, sequence, flags, version, body) VALUES (?,?,?,?,?)',
                    (key, sequence, flags, version, body))
    else:
        con.execute(f'INSERT INTO "{table}" VALUES (?,?,?,?,?,?,?)',
                    (key, sequence, flags, version, body, extra, expiration))
