# cblite-parser

A read-only reader for Couchbase Lite databases and the Fleece documents inside them,
written for digital forensics work. Pure Python, no dependencies, Python 3.10 or later.

Couchbase Lite is an embedded document database for mobile and desktop apps. A database
is a `<name>.cblite2` directory holding `db.sqlite3` (with its `-wal` and `-shm`) and an
`Attachments` directory of blob files. The SQLite part opens in any viewer, but the
document bodies are Fleece, Couchbase's binary JSON-like encoding, and their keys are
mostly small integers. Without the database's own key table you get values with no names.
This tool reads all of it.

## What it reads

- Every document of every collection, current body decoded, with its revision ID, its
  sequence and its flags (deleted, conflicted, has attachments, pushed to a server).
- The revision tree. Couchbase Lite keeps the IDs of earlier revisions, and sometimes
  their bodies, so an older version of a document can still be in the file.
- Tombstones, the rows of the `kv_del_` tables that deleted documents move to.
- The database's own records in `kv_info`: the shared key table, the document versioning,
  the UUIDs, the replication servers it talks to and the replicator's cookies.
- Blob references, with the blob file each one names and whether that file's SHA-1
  matches the digest the document recorded. Blob files no document names are listed too.
- Both layouts in use: the 2.x schema, where the whole revision tree sits in `body`, and
  the 3.x schema, where `body` holds the current revision and `extra` holds the tree.
- Rows that live only in the `-wal`. On two of the four stores this was tested on, the
  newest revisions were there and nowhere else.

## What it does not do

- Open the database in place. A read-only SQLite open with a `-wal` beside it still writes
  the `-shm`, so the database and its sidecars are copied to a temporary directory and the
  copy is read. The originals are not modified; a test checks the hashes.
- Decrypt. Enterprise Edition databases and blobs can be encrypted; an encrypted
  database is reported as unreadable, not guessed at.
- Decode version vectors. Databases that use version vectors (versioning 2) keep remote
  revisions in `extra` as Fleece that can point back into `body`. That layout is reported
  as present, not decoded, and the revision ID is printed as stored hex.
- Follow extern pointers. A delta-encoded Fleece document points into a base document it
  does not carry. Those pointers are refused rather than resolved against the wrong data.
- Recover deleted rows from SQLite free pages or old WAL frames. It reads what the
  database holds now.

## Usage

```
python -m cblite_parser info  path/to/app.cblite2
python -m cblite_parser dump  path/to/app.cblite2 [--collection scope.name] [--revisions] [--no-tombstones]
python -m cblite_parser blobs path/to/app.cblite2
python -m cblite_parser fleece some.fleece [--shared-keys-from path/to/app.cblite2]
```

`<store>` can be the `.cblite2` directory or its `db.sqlite3`. `pip install .` adds a
`cblite-parser` command that does the same.

- `info` prints the database's own records and a count of documents and tombstones per
  collection, as JSON.
- `dump` prints one JSON object per document, one per line. `--revisions` adds the
  revision tree, with any older body it kept. Binary values print as
  `{"$base64": "..."}` and non-finite floats as `{"$float": "nan"}`, so every line is
  strict JSON.
- `blobs` prints one tab-separated line per blob reference, then the orphan files.
- `fleece` decodes a raw Fleece file, for a blob carved or copied out of somewhere else.

From Python:

```python
from cblite_parser import Store, decode_fleece

with Store('app.cblite2') as store:
    print(store.versioning, len(store.shared_keys or []))
    for doc in store.documents():
        print(doc.collection, doc.key, doc.revid, doc.deleted, doc.body)
        for rev in doc.revisions[1:]:
            if rev.has_body:
                print('  older revision', rev.revid, rev.body)
```

## The format, briefly

Everything here is cited to two pinned commits:
[couchbase/fleece@8ce5f69](https://github.com/couchbase/fleece/tree/8ce5f690480b77c0f93d03f456a29828b5a55d66)
and [couchbase/couchbase-lite-core@3f90f2e](https://github.com/couchbase/couchbase-lite-core/tree/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f).
This is an independent implementation written from those sources; it contains no
Couchbase code.

**Fleece values** are two-byte aligned and the top four bits of the first byte are the
type ([Fleece.md L80](https://github.com/couchbase/fleece/blob/8ce5f690480b77c0f93d03f456a29828b5a55d66/Fleece.md#L80)).
The root is found from the end: the last two bytes, followed as a narrow pointer, then once
more as a wide pointer when that lands on another pointer
([Fleece.md L68](https://github.com/couchbase/fleece/blob/8ce5f690480b77c0f93d03f456a29828b5a55d66/Fleece.md#L68),
[Value.cc L334](https://github.com/couchbase/fleece/blob/8ce5f690480b77c0f93d03f456a29828b5a55d66/Fleece/Core/Value.cc#L334)).
Three details are easy to get wrong:

- A collection count of 2047 means 2047 **plus** a varint that follows, padded to an even
  length ([Array.cc L39](https://github.com/couchbase/fleece/blob/8ce5f690480b77c0f93d03f456a29828b5a55d66/Fleece/Core/Array.cc#L39),
  [L47](https://github.com/couchbase/fleece/blob/8ce5f690480b77c0f93d03f456a29828b5a55d66/Fleece/Core/Array.cc#L47)).
- A dictionary key of -2048 is not data. Its value is a parent dictionary this one
  inherits from, and a value of `undefined` deletes an inherited key
  ([Fleece.md L44](https://github.com/couchbase/fleece/blob/8ce5f690480b77c0f93d03f456a29828b5a55d66/Fleece.md#L44)).
- Bit `0x40` of a pointer marks it extern
  ([Pointer.hh L28](https://github.com/couchbase/fleece/blob/8ce5f690480b77c0f93d03f456a29828b5a55d66/Fleece/Core/Pointer.hh#L28)),
  but data written before that flag existed used fifteen-bit offsets, so the same bit is
  just part of a long backward offset. Fleece falls back to that reading for a narrow
  pointer when there is no base document and the target lands inside the data
  ([Pointer.cc L43](https://github.com/couchbase/fleece/blob/8ce5f690480b77c0f93d03f456a29828b5a55d66/Fleece/Core/Pointer.cc#L43)),
  and so does this reader. On one of the test stores, 197 documents needed it.

**Shared keys.** Integer dictionary keys index the array stored in `kv_info` under
`SharedKeys`. `kv_info` mixes encodings: `SharedKeys`, `remotes` and
`org.couchbase.cookies` are Fleece
([DatabaseImpl.cc L973](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/LiteCore/Database/DatabaseImpl.cc#L973),
[DatabaseCookies.cc L44](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/Replicator/DatabaseCookies.cc#L44),
[CookieStore.cc L207](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/Networking/HTTP/CookieStore.cc#L207)),
`versioning` is an eight-byte big-endian integer
([Record.cc L36](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/LiteCore/Storage/Record.cc#L36),
[DatabaseImpl.cc L197](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/LiteCore/Database/DatabaseImpl.cc#L197)),
and the UUIDs are sixteen raw bytes
([DatabaseImpl.cc L509](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/LiteCore/Database/DatabaseImpl.cc#L509)).
Decoding every `kv_info` value as Fleece gives plausible nonsense for the UUIDs.

**Versioning** 0 is revision trees in the 2.x schema, 1 is revision trees in the 3.x
schema, 2 is version vectors
([c4DatabaseTypes.h L162](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/C/include/c4DatabaseTypes.h#L162)).
Where the tree lives is decided per record, the way LiteCore decides it: in `extra` when
there is one, unless the revision ID is a version or `extra` starts with four zero bytes;
otherwise in `body` when it frames as a tree
([VectorRecord.cc L154](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/LiteCore/RevTrees/VectorRecord.cc#L154),
[L169](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/LiteCore/RevTrees/VectorRecord.cc#L169)).

**Revision trees** are a list of revisions, each a big-endian size, parent index, flags and
revision ID length, then the revision ID, a varint sequence and, when flag `0x80` is set,
the body
([RawRevTree.hh L53](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/LiteCore/RevTrees/RawRevTree.hh#L53),
[L58](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/LiteCore/RevTrees/RawRevTree.hh#L58)).
A zero size ends the list, and pairs of remote database ID and revision index follow, up
to a zero mark
([RawRevTree.cc L50](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/LiteCore/RevTrees/RawRevTree.cc#L50)).
The current revision is first, and a stored sequence of 0 means the record's own
([RawRevTree.cc L62](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/LiteCore/RevTrees/RawRevTree.cc#L62)).
Revision flags are in
[RevTree.hh L59](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/LiteCore/RevTrees/RevTree.hh#L59).
A tree revision ID is a varint generation and a digest, printed `<generation>-<hex>`; one
whose first byte is zero is a version
([RevID.hh L65](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/LiteCore/RevTrees/RevID.hh#L65)).

**Tables.** Each collection is a `kv_` table, with `kv_del_` beside it for tombstones
([SQLiteKeyStore.cc L77](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/LiteCore/Storage/SQLiteKeyStore.cc#L77)).
`kv_default` is the default collection; any other is `kv_.<name>` or `kv_.<scope>.<name>`,
with a backslash before each capital letter
([DatabaseImpl.cc L573](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/LiteCore/Database/DatabaseImpl.cc#L573),
[SQLiteKeyStore.cc L261](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/LiteCore/Storage/SQLiteKeyStore.cc#L261)).
The low sixteen bits of `flags` are the document flags
([Record.hh L20](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/LiteCore/Storage/Record.hh#L20),
[SQLiteKeyStore.cc L247](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/LiteCore/Storage/SQLiteKeyStore.cc#L247));
the bits above hold a subsequence number
([SQLiteKeyStore.cc L244](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/LiteCore/Storage/SQLiteKeyStore.cc#L244)). `expiration` is milliseconds since the
Unix epoch
([KeyStore.cc L87](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/LiteCore/Storage/KeyStore.cc#L87)).

**Blobs.** A document refers to a blob with a dictionary whose `@type` is `blob` and whose
`digest` is `sha1-` plus the base64 SHA-1 of the content, or through the older
`_attachments` dictionary
([c4BlobStore.hh L41](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/C/Cpp_include/c4BlobStore.hh#L41),
[L44](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/C/Cpp_include/c4BlobStore.hh#L44),
[L58](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/C/Cpp_include/c4BlobStore.hh#L58)).
The file is `Attachments/<base64 digest with / turned into _>.blob`
([c4BlobStore.cc L73](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/C/c4BlobStore.cc#L73),
[DatabaseImpl.cc L365](https://github.com/couchbase/couchbase-lite-core/blob/3f90f2e97b9a07ca84af6ea56a8b1b0d25860e1f/LiteCore/Database/DatabaseImpl.cc#L365)).
An app can also keep its files outside the database and record its own link to them, as
KeepSafe does with a hash in the document; this tool reports only the blobs Couchbase
Lite manages.

## What has been tested on real data

Four stores from two public research extractions, read and compared with an independent
count and with a second decoder:

| store | versioning | documents | body errors | older bodies kept |
| --- | --- | --- | --- | --- |
| a photo vault app's store, iOS 17.5.1 | 1 | 30 | 0 | 1 |
| a theme park app's facility store, iOS 12.4 | 0 | 7,172 | 0 | 62 |
| the same app's dashboard store | 0 | 22 | 0 | 0 |
| the copy of the facility store shipped inside the app | 0 | 5,861 | 0 | 0 |

Document counts equal a direct `COUNT(*)` of the tables. Every current body equals what a
second decoder produced (the one in iLEAPP's KeepSafe artifact), except 197 documents
of the shipped copy that the second decoder refused at a legacy pointer. Those 197 keep
Fleece's own invariants (sorted keys, valid UTF-8) and carry the same `name` as their newer
revision in the device's copy (196 the same `id`).

Present in the code and covered by hand-built tests, but not seen in real data yet:
named collections, tombstone rows, blob references and blob files, expiration values,
and version-vector databases. A store that has any of these would close the gap.

## Tests

```
python -m unittest discover -s tests -p 'test_*.py' -v
```

The fixtures are built by hand to the on-disk layout (`tests/builders.py`), and the two
documents from Fleece.md are typed in byte for byte, so the repository carries no sample
data.

## Licence

MIT. See `LICENSE`.
