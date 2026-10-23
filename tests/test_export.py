"""The export command: files written, escaping, image copies, provenance, refusals."""
import base64
import csv
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from cblite_parser import blob_filename  # noqa: E402
from cblite_parser.export import export  # noqa: E402
from builders import fleece, make_store, rev_tree, revid  # noqa: E402

PNG = (b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f'
       b'\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\xcf\xc0\xf0\x1f\x00\x05\x00\x01\xff\x89\x99=\x1d\x00'
       b'\x00\x00\x00IEND\xaeB`\x82')
HOSTILE = '<script>alert(1)</script><img src=x onerror=alert(2)>'


def digest_of(data):
    return 'sha1-' + base64.b64encode(hashlib.sha1(data).digest()).decode('ascii')


class Export(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.store = os.path.join(cls.tmp.name, 'app.cblite2')
        att = os.path.join(cls.store, 'Attachments')
        os.makedirs(att)
        with open(os.path.join(att, blob_filename(digest_of(PNG))), 'wb') as handle:
            handle.write(PNG)
        with open(os.path.join(att, blob_filename(digest_of(b'not referenced'))), 'wb') as handle:
            handle.write(b'not referenced')
        body = fleece({'title': HOSTILE, 'pic': {'@type': 'blob', 'digest': digest_of(PNG),
                                                 'content_type': 'image/png', 'length': len(PNG)}})
        older = fleece({'title': 'before'})
        extra = rev_tree([(revid(2, 'bb'), 1, 0x02, 0, None), (revid(1, 'aa'), None, 0, 1, older)])
        make_store(cls.store, {
            'kv_default': [('doc-1', 2, 0x0C, revid(2, 'bb'), body, extra, None),
                           (HOSTILE, 3, 0, revid(1, 'cc'), fleece({'n': 1}), None, None)],
            'kv_del_default': [('gone', 1, 1, revid(1, 'dd'), None, None, None)],
        }, info={'versioning': (1).to_bytes(8, 'big')})
        cls.out = os.path.join(cls.tmp.name, 'out')
        cls.info = export(cls.store, cls.out)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def read(self, name):
        return pathlib.Path(self.out, name).read_text(encoding='utf-8')

    def rows(self, name):
        with open(os.path.join(self.out, name), encoding='utf-8', newline='') as handle:
            return list(csv.DictReader(handle))

    def test_files_written(self):
        for name in ('index.html', 'documents.csv', 'revisions.csv', 'blobs.csv', 'export_info.json'):
            self.assertTrue(os.path.isfile(os.path.join(self.out, name)), name)
        self.assertEqual(json.loads(self.read('export_info.json'))['files'], self.info['files'])

    def test_csv_rows(self):
        docs = self.rows('documents.csv')
        self.assertEqual(len(docs), 3)
        self.assertEqual(json.loads(docs[0]['body_json'])['title'], HOSTILE)
        self.assertEqual(docs[0]['older_bodies'], '1')
        revs = self.rows('revisions.csv')
        self.assertEqual([r['revid'][:2] for r in revs], ['2-', '1-'])
        self.assertEqual(revs[0]['body_json'], '')            # the current body is in documents.csv
        self.assertEqual(json.loads(revs[1]['body_json']), {'title': 'before'})
        blobs = self.rows('blobs.csv')
        self.assertEqual([b['orphan'] for b in blobs], ['False', 'True'])
        self.assertEqual(blobs[0]['sha1_matches'], 'True')

    def test_html_escapes_evidence_and_loads_nothing_external(self):
        page = self.read('index.html')
        self.assertNotIn('<script>alert', page)
        self.assertNotIn('<img src=x', page)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', page)
        self.assertIn("default-src 'none'", page)
        self.assertNotIn('http://', page.split('</head>')[0].replace('http-equiv', ''))
        self.assertEqual(page.count('<script>'), 1)
        data = page.split('id="docdata">', 1)[1].split('</script>', 1)[0]
        self.assertNotIn('<', data)
        self.assertEqual(json.loads(data)[0]['body']['title'], HOSTILE)

    def test_image_blob_copied_and_shown(self):
        name = hashlib.sha1(PNG).hexdigest() + '.png'
        self.assertEqual(pathlib.Path(self.out, 'blobs', name).read_bytes(), PNG)
        self.assertIn(f'src="blobs/{name}"', self.read('index.html'))
        self.assertEqual(os.listdir(os.path.join(self.out, 'blobs')), [name])

    def test_source_hashes(self):
        db = os.path.join(self.store, 'db.sqlite3')
        recorded = {s['path']: s['sha256'] for s in self.info['source_files']}
        self.assertEqual(recorded[os.path.abspath(db)], hashlib.sha256(pathlib.Path(db).read_bytes()).hexdigest())
        self.assertEqual(self.info['collections']['_default._default'], {'documents': 2, 'tombstones': 1})

    def test_refuses_a_folder_that_is_not_empty(self):
        with self.assertRaises(FileExistsError):
            export(self.store, self.out)

    def test_cli(self):
        out = os.path.join(self.tmp.name, 'cli-out')
        result = subprocess.run([sys.executable, '-m', 'cblite_parser', 'export', self.store, out],
                                cwd=REPO_ROOT, capture_output=True, text=True, stdin=subprocess.DEVNULL, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('3 documents', result.stderr)
        again = subprocess.run([sys.executable, '-m', 'cblite_parser', 'export', self.store, out],
                               cwd=REPO_ROOT, capture_output=True, text=True, stdin=subprocess.DEVNULL, check=False)
        self.assertEqual(again.returncode, 1)
        self.assertIn('not empty', again.stderr)


if __name__ == '__main__':
    unittest.main()
