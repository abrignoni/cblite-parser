"""Exercise ``python -m cblite_parser`` end to end, as a subprocess."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from builders import fleece, make_store, rev_tree, revid  # noqa: E402

KEYS = ['name', 'raw']


def run(*args, stdin=subprocess.DEVNULL):
    return subprocess.run([sys.executable, '-m', 'cblite_parser', *args], cwd=REPO_ROOT,
                          capture_output=True, text=True, stdin=stdin, check=False)


class CLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.store = os.path.join(cls.tmp.name, 'x.cblite2')
        body = fleece({'name': 'tab\there', 'raw': b'\x00\x01', 'n': float('inf')}, KEYS)
        older = fleece({'name': 'before'}, KEYS)
        extra = rev_tree([(revid(2, 'bb'), 1, 0x02, 0, None), (revid(1, 'aa'), None, 0, 1, older)])
        make_store(cls.store, {
            'kv_default': [(f'doc{i}', i + 2, 0, revid(2, 'bb'), body, extra if i == 0 else None, None)
                           for i in range(300)],
            'kv_del_default': [('dead', 1, 1, revid(1, 'cc'), None, None, None)],
        }, info={'SharedKeys': fleece(KEYS), 'versioning': (1).to_bytes(8, 'big')})
        with open(os.path.join(cls.tmp.name, 'doc.fleece'), 'wb') as handle:
            handle.write(fleece({'name': 'loose'}, KEYS))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_dump_is_strict_json_lines(self):
        result = run('dump', self.store)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(rows), 301)
        self.assertEqual(rows[0]['body']['raw'], {'$base64': 'AAE='})
        self.assertEqual(rows[0]['body']['n'], {'$float': 'inf'})
        self.assertEqual(rows[0]['body']['name'], 'tab\there')
        self.assertTrue(rows[-1]['deleted'] and rows[-1]['tombstone_table'])

    def test_dump_revisions_and_filters(self):
        rows = [json.loads(line) for line in run('dump', '--revisions', '--no-tombstones', self.store).stdout.splitlines()]
        self.assertEqual(len(rows), 300)
        self.assertEqual(rows[0]['revisions'][1]['body'], {'name': 'before'})

    def test_info(self):
        data = json.loads(run('info', self.store).stdout)
        self.assertEqual(data['versioning'], 1)
        self.assertEqual(data['collections']['_default._default'], {'documents': 300, 'tombstones': 1})

    def test_fleece_with_shared_keys(self):
        path = os.path.join(self.tmp.name, 'doc.fleece')
        self.assertEqual(json.loads(run('fleece', path).stdout), {'0': 'loose'})
        self.assertEqual(json.loads(run('fleece', path, '--shared-keys-from', self.store).stdout), {'name': 'loose'})

    def test_errors_exit_one(self):
        result = run('dump', os.path.join(self.tmp.name, 'nope.cblite2'))
        self.assertEqual(result.returncode, 1)
        self.assertIn('error:', result.stderr)

    def test_closed_pipe_exits_quietly(self):
        proc = subprocess.Popen([sys.executable, '-m', 'cblite_parser', 'dump', self.store], cwd=REPO_ROOT,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
        proc.stdout.close()
        _, err = proc.communicate()
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn(b'Traceback', err)


if __name__ == '__main__':
    unittest.main()
