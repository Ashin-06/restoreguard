"""Real HTTP, CLI and evidence checks for the local prototype."""

import contextlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import zipfile

from restoreguard.cli import main
from restoreguard.evidence import bundle_case, list_cases, load_case, run_case, verify_case
from restoreguard.reports import render_report
from restoreguard.server import create_server


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_run_preserves_real_sqlite_and_manifest(self):
        case = run_case(self.root, max_experiments=2, repeats=1)
        folder = self.root / case['case_id']
        self.assertEqual('FAIL', case['result']['status'])
        self.assertEqual('PASS', verify_case(folder)['status'])
        self.assertEqual(case, load_case(self.root, case['case_id']))
        self.assertEqual(1, len(list_cases(self.root)))
        databases = list((folder / 'fixtures').rglob('*.sqlite'))
        self.assertGreaterEqual(len(databases), 10)
        for database in databases:
            with contextlib.closing(sqlite3.connect(database)) as db:
                self.assertEqual('ok', db.execute('PRAGMA integrity_check').fetchone()[0])
        with zipfile.ZipFile(io.BytesIO(bundle_case(self.root, case['case_id']))) as archive:
            self.assertIsNone(archive.testzip())
            self.assertIn(case['case_id'] + '/manifest.json', archive.namelist())

    def test_tamper_missing_extra_and_export_refusal(self):
        case = run_case(self.root, max_experiments=1, repeats=1)
        folder = self.root / case['case_id']
        (folder / 'report.html').write_text('changed', encoding='utf-8')
        (folder / 'fixtures.json').unlink()
        (folder / 'extra.txt').write_text('extra', encoding='utf-8')
        result = verify_case(folder)
        self.assertEqual('FAIL', result['status'])
        self.assertEqual(3, len(result['errors']))
        with self.assertRaises(ValueError):
            bundle_case(self.root, case['case_id'])

    def test_traversal_and_empty_manifest_rejected(self):
        case = run_case(self.root, max_experiments=1, repeats=1)
        folder = self.root / case['case_id']
        manifest = json.loads((folder / 'manifest.json').read_text(encoding='utf-8'))
        manifest['files']['../outside'] = 'fake'
        (folder / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
        self.assertIn('Unsafe manifest path', ' '.join(verify_case(folder)['errors']))
        (folder / 'manifest.json').write_text('{"algorithm":"sha256","files":{}}', encoding='utf-8')
        self.assertEqual('FAIL', verify_case(folder)['status'])
        with self.assertRaises(ValueError):
            load_case(self.root, '../outside')

    def test_report_escaping(self):
        case = run_case(self.root, max_experiments=1, repeats=1)
        case['result']['results'][0]['observations'][0]['actor'] = '<script>alert(1)</script>'
        html = render_report(case)
        self.assertNotIn('<script>', html)
        self.assertIn('&lt;script&gt;', html)

    def test_cli_exit_codes_and_bundle_roundtrip(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(1, main(['matrix', '--budget', '1', '--repeats', '1', '--output-dir', str(self.root)]))
            self.assertEqual(2, main(['matrix', '--mode', 'protected', '--budget', '1', '--output-dir', str(self.root)]))
            self.assertEqual(2, main(['matrix', '--budget', '0', '--output-dir', str(self.root)]))
            self.assertEqual(2, main(['minimize', '--selection', 'A,B']))
            folder = next(p for p in self.root.iterdir() if p.is_dir())
            output = self.root / 'evidence.zip'
            self.assertEqual(0, main(['verify', str(folder)]))
            self.assertEqual(0, main(['bundle', str(folder), '--output', str(output)]))
            self.assertEqual(2, main(['bundle', str(folder), '--output', str(output)]))
            self.assertEqual(2, main(['bundle', str(folder), '--output', str(folder / 'bad.zip')]))
        self.assertTrue(output.is_file())


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.server = create_server(0, cls.temp.name)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.temp.cleanup()

    def request(self, path, data=None, headers=None):
        request = Request(self.url + path, data=json.dumps(data).encode() if data is not None else None,
                          headers={'Content-Type': 'application/json', **(headers or {})})
        try:
            with urlopen(request, timeout=90) as response:
                return response.status, response.read(), response.headers
        except HTTPError as response:
            return response.code, response.read(), response.headers

    def test_matrix_download_reduce_and_scenarios(self):
        self.assertEqual(200, self.request('/api/demo')[0])
        status, payload, headers = self.request('/api/run', {'mode': 'vulnerable', 'max_experiments': 1, 'repeats': 1})
        self.assertEqual(200, status)
        self.assertEqual('no-store', headers['Cache-Control'])
        case = json.loads(payload)
        self.assertEqual('FAIL', case['result']['status'])
        self.assertEqual(200, self.request(case['artifacts']['report'])[0])
        self.assertEqual(200, self.request(case['artifacts']['bundle'])[0])
        self.assertEqual('PASS', json.loads(self.request('/api/cases/' + case['case_id'] + '/verify')[1])['status'])
        status, payload, _ = self.request('/api/minimize', {})
        self.assertEqual(200, status)
        self.assertTrue(json.loads(payload)['one_minimal'])
        status, payload, _ = self.request('/api/scenarios', {})
        self.assertEqual(200, status)
        self.assertEqual('PASS', json.loads(payload)['status'])

    def test_guards_bad_inputs_and_source_is_not_served(self):
        self.assertEqual(403, self.request('/api/run', {}, {'Origin': 'https://example.com'})[0])
        self.assertEqual(403, self.request('/api/demo', headers={'Host': 'attacker.invalid'})[0])
        self.assertEqual(415, self.request('/api/run', {}, {'Content-Type': 'text/plain'})[0])
        for body in ({'mode': 'invalid'}, {'repeats': True}, {'max_experiments': 28}, {'repeats': 0}, []):
            self.assertEqual(400, self.request('/api/run', body)[0])
        self.assertEqual(400, self.request('/api/minimize', {'selection': 'bad'})[0])
        self.assertEqual(404, self.request('/restoreguard/core.py')[0])
        self.assertEqual(404, self.request('/api/unknown')[0])


if __name__ == '__main__':
    unittest.main()
