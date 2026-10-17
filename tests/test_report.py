"""Synthetic fixtures exercise reporting without Docker, credentials or sockets."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import report


class ReportTests(unittest.TestCase):
    def temp_root(self):
        path = Path(__file__).resolve().parents[1] / 'tmp' / 'report-tests'
        path.mkdir(parents=True, exist_ok=True)
        return path
    def run_fixture(self, root, phase, controls):
        path = root/'evidence'/('fixture-'+phase); path.mkdir(parents=True)
        files = {
            'checks.json': json.dumps({'run_id': path.name, 'controls': controls}),
            'inventory.json': json.dumps([{'asset': 'synthetic-fileserver', 'ports': []}]),
            'inventory.md': '# Live asset inventory\n\n| Asset | IP | TCP port | Service | Version |\n|---|---|---|---|---|\n| synthetic-fileserver | 172.20.0.3 | 445 | SMB | fixture |\n',
            'nuclei-normalized.json': '[]'}
        for name, value in files.items(): (path/name).write_text(value, encoding='utf-8')
        hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in path.iterdir()}
        (path/'sha256.json').write_text(json.dumps(hashes))
        return path

    def test_failed_retest_is_open_in_all_outputs(self):
        with tempfile.TemporaryDirectory(dir=self.temp_root()) as directory:
            root=Path(directory)
            base=self.run_fixture(root,'baseline',{'smb_signing_required': False})
            current=self.run_fixture(root,'retest',{'smb_signing_required': False})
            with patch.object(report, 'ROOT', root): rows=report.generate(current, root/'output')
            self.assertEqual(rows[0]['status'], 'Open')
            self.assertIn('0 fixed and retested', (root/'output/security-assessment.md').read_text())
            self.assertTrue((root/'output/security-assessment.pdf').read_bytes().startswith(b'%PDF'))
            self.assertIn('<table>', (root/'output/index.html').read_text())

    def test_tampered_raw_evidence_stops_report_generation(self):
        with tempfile.TemporaryDirectory(dir=self.temp_root()) as directory:
            root=Path(directory)
            current=self.run_fixture(root,'retest',{})
            (current/'inventory.md').write_text('tampered')
            with patch.object(report,'ROOT',root), self.assertRaisesRegex(ValueError,'hash mismatch'):
                report.generate(current,root/'output')


if __name__ == '__main__': unittest.main()
