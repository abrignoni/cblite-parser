"""Blob references and the Attachments directory (c4BlobStore.cc, c4BlobStore.hh)."""
import base64
import hashlib
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from cblite_parser import Store, blob_filename, iter_blob_refs  # noqa: E402
from builders import fleece, make_store, revid  # noqa: E402


def digest_of(data):
    return 'sha1-' + base64.b64encode(hashlib.sha1(data).digest()).decode('ascii')


class Filenames(unittest.TestCase):
    def test_slash_becomes_underscore(self):
        # find content whose base64 digest holds a '/'
        for i in range(1000):
            data = str(i).encode()
            d = digest_of(data)
            if '/' in d:
                break
        name = blob_filename(d)
        self.assertNotIn('/', name)
        self.assertTrue(name.endswith('.blob'))
        self.assertEqual(name[:-5].replace('_', '/'), d[5:])

    def test_not_a_sha1_digest(self):
        for bad in (None, '', 'md5-abc', 'sha1-not base64!', 'sha1-' + base64.b64encode(b'short').decode()):
            self.assertIsNone(blob_filename(bad))


class References(unittest.TestCase):
    def test_typed_blob_and_legacy_attachments(self):
        body = {'pic': {'@type': 'blob', 'digest': 'sha1-x', 'length': 3, 'content_type': 'image/png'},
                'list': [{'@type': 'blob', 'data': b'abc'}],
                '_attachments': {'old.jpg': {'digest': 'sha1-y', 'length': 9}}}
        refs = {r.path: r for r in iter_blob_refs(body)}
        self.assertEqual(set(refs), {'$.pic', '$.list[0]', '$._attachments.old.jpg'})
        self.assertTrue(refs['$._attachments.old.jpg'].legacy)
        self.assertEqual(refs['$.list[0]'].inline_bytes, 3)


class Files(unittest.TestCase):
    def test_present_matching_mismatched_missing_and_orphan(self):
        with tempfile.TemporaryDirectory() as tmp:
            good, bad, missing, orphan = b'good bytes', b'tampered', b'never written', b'nobody'
            att = os.path.join(tmp, 'Attachments')
            os.makedirs(att)
            for data, content in ((good, good), (bad, b'something else'), (orphan, orphan)):
                with open(os.path.join(att, blob_filename(digest_of(data))), 'wb') as handle:
                    handle.write(content)
            body = {'a': {'@type': 'blob', 'digest': digest_of(good)},
                    'b': {'@type': 'blob', 'digest': digest_of(bad)},
                    'c': {'@type': 'blob', 'digest': digest_of(missing)}}
            make_store(tmp, {'kv_default': [('d', 1, 0x04, revid(1, 'aa'), fleece(body), None, None)]},
                       info={'versioning': (1).to_bytes(8, 'big')})
            with Store(tmp) as store:
                rows = {ref.path: (path, match) for _doc, ref, path, match in store.blobs()}
                orphans = store.orphan_blob_files()
            self.assertTrue(rows['$.a'][1])
            self.assertIs(rows['$.b'][1], False)
            self.assertEqual(rows['$.c'], (None, None))
            self.assertEqual(orphans, [blob_filename(digest_of(orphan))])


if __name__ == '__main__':
    unittest.main()
