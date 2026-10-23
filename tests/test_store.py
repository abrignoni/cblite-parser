"""Store-level tests on hand-built LiteCore databases (see builders.py)."""
import hashlib
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from cblite_parser import CBLiteError, Store, collection_name, format_revid  # noqa: E402
from builders import fleece, make_store, rev_tree, revid  # noqa: E402

KEYS = ['modelType', 'name', 'albumId', 'photo']
SK = fleece(KEYS)
R1, R2, R3 = revid(1, 'aa' * 20), revid(2, 'bb' * 20), revid(3, 'cc' * 20)


def info(versioning):
    return {
        'SharedKeys': SK,
        'versioning': versioning.to_bytes(8, 'big'),
        'publicUUID': bytes(range(16)),
        'remotes': fleece({'wss://sync.example.test/db/_blipsync': 1}),
    }


def tree_files(paths):
    return {p: hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
            for p in paths if os.path.exists(p)}


class ThreeX(unittest.TestCase):
    """3.x revision-tree schema: body is the current revision's Fleece, extra the tree."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = os.path.join(self.tmp.name, 'vault.cblite2')
        album = fleece({'modelType': 'album', 'name': 'Main'}, KEYS)
        file_v3 = fleece({'modelType': 'file', 'albumId': 'a1', 'photo': {'w': 640}}, KEYS)
        file_v2 = fleece({'modelType': 'file', 'albumId': 'old'}, KEYS)
        extra = rev_tree([(R3, 1, 0x02, 0, None), (R2, 2, 0x00, 7, file_v2), (R1, None, 0, 6, None)],
                         remotes={1: 0})
        self.path, _ = make_store(self.dir, {
            'kv_default': [('a1', 5, 0x10008, R1, album, None, None),
                           ('f1', 9, 0x08, R3, file_v3, extra, 1735689600000)],
            'kv_del_default': [('gone', 4, 0x01, R2, None, None, None)],
            'kv_.Shop.\\Items': [('i1', 1, 0, R1, fleece({'name': 'x'}, KEYS), None, None)],
        }, info=info(1))

    def tearDown(self):
        self.tmp.cleanup()

    def test_info_values_read_as_litecore_writes_them(self):
        with Store(self.dir) as store:
            self.assertEqual(store.versioning, 1)
            self.assertEqual(store.shared_keys, KEYS)
            self.assertEqual(store.info['publicUUID'], bytes(range(16)).hex())
            self.assertEqual(store.info['remotes'], {'wss://sync.example.test/db/_blipsync': 1})

    def test_collections_and_unmangled_names(self):
        with Store(self.dir) as store:
            self.assertEqual(set(store.collections()), {'_default._default', 'Shop.Items'})

    def test_documents_flags_revid_and_body(self):
        with Store(self.path) as store:
            docs = {d.key: d for d in store.documents()}
        self.assertEqual(docs['a1'].body, {'modelType': 'album', 'name': 'Main'})
        self.assertEqual(docs['a1'].flags, ['synced'])
        self.assertEqual(docs['a1'].subsequence, 1)
        self.assertEqual(docs['a1'].revid, '1-' + 'aa' * 20)
        self.assertEqual(docs['f1'].body['photo'], {'w': 640})
        self.assertEqual(docs['f1'].expiration_utc.isoformat(), '2025-01-01T00:00:00+00:00')
        self.assertTrue(docs['gone'].deleted and docs['gone'].tombstone_table)
        self.assertEqual(docs['i1'].collection, 'Shop.Items')

    def test_revision_tree_in_extra_keeps_an_older_body(self):
        with Store(self.dir) as store:
            doc = next(d for d in store.documents() if d.key == 'f1')
        self.assertEqual([r.revid[:2] for r in doc.revisions], ['3-', '2-', '1-'])
        self.assertEqual(doc.revisions[0].sequence, 9)       # stored 0, takes the record's
        self.assertEqual(doc.revisions[0].flags, ['leaf'])
        self.assertEqual(doc.revisions[1].body, {'modelType': 'file', 'albumId': 'old'})
        self.assertFalse(doc.revisions[2].has_body)
        self.assertEqual(doc.remote_revisions, {1: 0})

    def test_originals_are_not_modified(self):
        before = tree_files([self.path, self.path + '-wal', self.path + '-shm'])
        with Store(self.dir) as store:
            list(store.documents())
        self.assertEqual(tree_files([self.path, self.path + '-wal', self.path + '-shm']), before)
        self.assertFalse(os.path.exists(self.path + '-shm'))


class TwoX(unittest.TestCase):
    """2.x schema: no extra column, body is the whole revision tree."""

    def test_current_body_comes_from_the_first_revision(self):
        with tempfile.TemporaryDirectory() as tmp:
            current = fleece({'name': 'new'}, KEYS)
            older = fleece({'name': 'old'}, KEYS)
            body = rev_tree([(R2, 1, 0x02, 0, current), (R1, None, 0, 3, older)])
            make_store(tmp, {'kv_default': [('d', 4, 0, R2, body, None, None)]},
                       info={'SharedKeys': SK, 'versioning': (0).to_bytes(8, 'big')}, v2=True)
            with Store(tmp) as store:
                doc = next(store.documents())
            self.assertEqual(doc.body, {'name': 'new'})
            self.assertEqual(doc.revisions[1].body, {'name': 'old'})
            self.assertEqual(doc.revisions[0].sequence, 4)


class WriteAheadLog(unittest.TestCase):
    def test_rows_only_in_the_wal_are_read_and_the_wal_is_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, con = make_store(tmp, {'kv_default': [('main', 1, 0, R1, fleece({'name': 'm'}, KEYS), None, None)]},
                                   info=info(1),
                                   wal_rows=[('kv_default', ('walonly', 2, 0, R1, fleece({'name': 'w'}, KEYS), None, None))])
            try:
                self.assertTrue(os.path.getsize(path + '-wal') > 0)
                before = tree_files([path, path + '-wal', path + '-shm'])
                with Store(tmp) as store:
                    keys = [d.key for d in store.documents()]
                    self.assertTrue(store.wal_present)
                self.assertEqual(keys, ['main', 'walonly'])
                self.assertEqual(tree_files([path, path + '-wal', path + '-shm']), before)
            finally:
                con.close()


class Refusals(unittest.TestCase):
    def test_not_sqlite(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, 'db.sqlite3'), 'wb') as handle:
                handle.write(os.urandom(4096))
            with self.assertRaises(CBLiteError):
                Store(tmp)

    def test_sqlite_without_litecore_tables(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as tmp:
            con = sqlite3.connect(os.path.join(tmp, 'db.sqlite3'))
            con.execute('CREATE TABLE t (x)')
            con.commit()
            con.close()
            with self.assertRaises(CBLiteError):
                Store(tmp)

    def test_undecodable_body_is_kept_with_its_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_store(tmp, {'kv_default': [('bad', 1, 0, R1, b'\x01\x02\x03', None, None)]}, info=info(1))
            with Store(tmp) as store:
                doc = next(store.documents())
            self.assertIsNone(doc.body)
            self.assertTrue(doc.body_error)


class Helpers(unittest.TestCase):
    def test_format_revid(self):
        self.assertEqual(format_revid(revid(300, 'ab')), '300-ab')
        self.assertEqual(format_revid(b'\x00\x01\x02'), 'v:000102')

    def test_collection_name(self):
        self.assertEqual(collection_name('kv_default'), '_default._default')
        self.assertEqual(collection_name('kv_del_.items'), '_default.items')
        self.assertEqual(collection_name('kv_.\\Shop.\\Items'), 'Shop.Items')
        self.assertIsNone(collection_name('kv_info'))


if __name__ == '__main__':
    unittest.main()
