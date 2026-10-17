import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from core import SERVICES, findings, parse_nmap, parse_nuclei, validate_scope, validate_target

FIX = Path(__file__).parent / 'fixtures'


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.records = [{'Id': s, 'Config': {'Labels': {'com.docker.compose.project': 'it-support-homelab', 'com.docker.compose.service': s}},
                         'State': {'Running': True}, 'NetworkSettings': {'Networks': {'office-lan': {'IPAddress': f'172.20.0.{i+2}'}},
                         'Ports': {'445/tcp': [{'HostIp': '127.0.0.1'}]}}} for i, s in enumerate(sorted(SERVICES))]
        self.members = {s: {} for s in SERVICES}
        self.scope = validate_scope(self.records, self.members)

    def test_five_verified_services(self):
        self.assertEqual(set(self.scope), SERVICES)

    def test_public_tls_proxy_is_refused_even_though_not_scanned(self):
        proxy = copy.deepcopy(self.records[0])
        proxy['Config']['Labels']['com.docker.compose.service'] = 'admin-tls'
        proxy['NetworkSettings']['Ports']['445/tcp'][0]['HostIp'] = '0.0.0.0'
        with self.assertRaises(ValueError):
            validate_scope(self.records+[proxy], self.members)

    def test_external_and_neighbor_targets_refused(self):
        for target in ['example.com', '8.8.8.8', '172.20.10.99', '172.20.0.0/16', '127.1', 'localhost.evil.test', '--script=all', 'http://fileserver', 'homepage', '::1']:
            with self.subTest(target=target), self.assertRaises(ValueError):
                validate_target(target, self.scope)

    def test_wrong_labels_network_address_or_publication_fail_closed(self):
        for mutation in ['project', 'subnet', 'binding', 'missing', 'stopped']:
            r = copy.deepcopy(self.records); members = copy.deepcopy(self.members)
            if mutation == 'project': r[0]['Config']['Labels']['com.docker.compose.project'] = 'other'
            if mutation == 'subnet': r[0]['NetworkSettings']['Networks']['office-lan']['IPAddress'] = '192.168.1.2'
            if mutation == 'binding': r[0]['NetworkSettings']['Ports']['445/tcp'][0]['HostIp'] = '0.0.0.0'
            if mutation == 'missing': del members[r[0]['Id']]
            if mutation == 'stopped': r[0]['State']['Running'] = False
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): validate_scope(r, members)


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.scope = {'fileserver': '172.20.0.3', 'uptime': '172.20.0.5'}

    def test_open_ports_only_and_versions(self):
        hosts = parse_nmap((FIX / 'nmap.xml').read_text(), self.scope)
        self.assertEqual(len(hosts), 1)
        self.assertEqual([p['port'] for p in hosts[0]['ports']], [445])
        self.assertIn('Samba', hosts[0]['ports'][0]['version'])

    def test_nmap_external_evidence_refused(self):
        with self.assertRaises(ValueError): parse_nmap((FIX / 'nmap.xml').read_text().replace('172.20.0.3', '8.8.8.8'), self.scope)

    def test_empty_scanner_is_not_error(self):
        self.assertEqual(parse_nuclei('', self.scope), [])

    def test_template_match_remains_informational(self):
        rows = parse_nuclei((FIX / 'nuclei.jsonl').read_text(), self.scope)
        self.assertEqual(rows[0]['severity'], 'info')

    def test_malformed_scanner_output_fails(self):
        with self.assertRaises(json.JSONDecodeError): parse_nuclei('not-json', self.scope)

    def test_out_of_scope_scanner_result_refused(self):
        with self.assertRaises(ValueError): parse_nuclei((FIX / 'nuclei.jsonl').read_text().replace('172.20.0.5', '8.8.8.8'), self.scope)

    def test_failed_and_unknown_retests_never_close(self):
        base = {'run_id': 'fixture-before', 'controls': {'smb_signing_required': False, 'ad_min_age': False, 'admin_tls': False}}
        current = {'run_id': 'fixture-after', 'controls': {'smb_signing_required': True, 'ad_min_age': False}}
        rows = findings(base, current)
        self.assertEqual([r['status'] for r in rows], ['Fixed - retested', 'Open', 'Not tested'])

    def test_no_fabricated_findings_without_baseline(self):
        base = {'run_id': 'fixture', 'controls': {}}
        self.assertEqual(findings(base, base), [])


if __name__ == '__main__': unittest.main()
