"""Synthetic field-contract cases, never presented as live alert evidence."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from soc_rules import CATALOG, counts, load_rules, matches, parse_event_xml
from monitoring_setup import NETWORK, VERSION, check_inventory, validate_deployment
from monitoring_collect import validate_container
from monitoring_publish import redact_public


def event(event_id, **data):
    return {'win': {'system': {'providerName': 'Microsoft-Windows-Security-Auditing',
            'eventID': str(event_id), 'channel': 'Security', 'computer': 'DC01.corp.lab',
            'keywords': '0x8010000000000000'}, 'eventdata': data}}


class DetectionTests(unittest.TestCase):
    def test_catalog_unique_and_mapped_to_xml(self):
        rules = {r.get('id'): r for r in load_rules()}
        self.assertEqual(len(CATALOG), len({c['rule'] for c in CATALOG}))
        for entry in CATALOG:
            self.assertEqual(entry['technique'], rules[entry['rule']].findtext('mitre/id'))

    def test_privileged_group_sid_and_ordinary_group(self):
        for eid in (4728, 4732, 4756):
            for sid in ('S-1-5-32-544', 'S-1-5-21-1-2-3-512', 'S-1-5-21-1-2-3-519'):
                self.assertIn('110101', matches(event(eid, targetSid=sid)))
        for sid in ('S-1-5-21-1-2-3-1512', 'S-1-5-21-1-2-3-1100', 'S-1-5-32-545', ''):
            self.assertNotIn('110101', matches(event(4728, targetSid=sid)))

    def test_lockout_requires_fictional_account_and_client(self):
        self.assertIn('110102', matches(event(4740, targetUserName='soc.lockout', targetDomainName='CLIENT01')))
        for data in ({'targetUserName': 'Administrator', 'targetDomainName': 'CLIENT01'},
                     {'targetUserName': 'soc.lockout', 'targetDomainName': 'UNOWNED'},
                     {'targetUserName': 'soc.lockout'}):
            self.assertNotIn('110102', matches(event(4740, **data)))

    def test_disabled_failure_status_and_substatus(self):
        self.assertIn('110103', matches(event(4625, targetUserName='soc.disabled', status='0xC0000072')))
        self.assertIn('110108', matches(event(4625, targetUserName='soc.disabled', subStatus='0xc0000072', status='0xc000006e')))
        self.assertFalse(matches(event(4625, targetUserName='soc.disabled', subStatus='0xc000006a')))
        self.assertFalse(matches(event(4624, targetUserName='soc.disabled', status='0xc0000072')))

    def test_new_service_requires_server(self):
        for eid in (4697, 7045):
            item = event(eid)
            if eid == 7045:
                item['win']['system']['channel'] = 'System'
                item['win']['system']['providerName'] = 'Service Control Manager'
            self.assertIn('110104', matches(item))
            item['win']['system']['computer'] = 'CLIENT01.corp.lab'
            self.assertNotIn('110104', matches(item))

    def test_task_creation_and_audit_policy_change(self):
        self.assertIn('110105', matches(event(4698)))
        self.assertIn('110106', matches(event(4719)))
        self.assertFalse(matches(event(4699)))

    def test_share_noise_tuning_preserves_failures(self):
        denied = event(5145, shareName='\\\\*\\SocRestricted')
        success = copy.deepcopy(denied)
        success['win']['system']['keywords'] = '0x8020000000000000'
        other = event(5145, shareName='\\\\*\\Public')
        self.assertIn('110107', matches(denied))
        self.assertNotIn('110107', matches(success))
        self.assertNotIn('110107', matches(other))
        # These are synthetic test counts, not a claim about actual noise reduction.
        self.assertEqual(counts([success, denied], True)['110107'], 2)
        self.assertEqual(counts([success, denied])['110107'], 1)

    def test_unowned_host_rejected_for_every_detection(self):
        for eid in (4728, 4740, 4625, 7045, 4698, 4719, 5145):
            item = event(eid, targetSid='S-1-5-32-544', targetUserName='soc.lockout', callerComputerName='CLIENT01')
            item['win']['system']['computer'] = 'OTHER.corp.lab'
            self.assertEqual(matches(item), [])

    def test_sysmon_context_is_not_incident(self):
        item = event(1)
        item['win']['system']['channel'] = 'Microsoft-Windows-Sysmon/Operational'
        self.assertEqual(matches(item), ['110109'])

    def test_windows_xml_normalization(self):
        text = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><Channel>Security</Channel><Computer>CLIENT01.corp.lab</Computer><EventRecordID>1</EventRecordID></System><EventData><Data Name="TargetUserName">soc.disabled</Data><Data Name="SubStatus">0xc0000072</Data></EventData></Event>'
        result = parse_event_xml(text)
        self.assertEqual(result['win']['system']['eventRecordID'], '1')
        self.assertIn('110108', matches(result))
        with self.assertRaises(ValueError):
            parse_event_xml('<Event/>')

    def test_unknown_rule_semantics_fail_closed(self):
        scratch = Path(__file__).resolve().parents[1] / 'tmp'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as tmp:
            path = Path(tmp) / 'rules.xml'
            path.write_text('<group><rule id="110001" level="5"><frequency>3</frequency></rule></group>')
            with self.assertRaises(ValueError):
                load_rules(path)

    def test_inventory_exact_owned_addresses(self):
        good = {'DC01': '192.168.77.10', 'CLIENT01': '192.168.77.100', 'switch': 'WindowsADLab-Internal', 'domain': 'corp.lab'}
        check_inventory(good)
        for key, value in [('DC01', '8.8.8.8'), ('CLIENT01', '192.168.77.151'), ('CLIENT01', '127.0.0.1'),
                           ('CLIENT01', 'example.com'), ('CLIENT01', '::1'), ('switch', 'External'), ('domain', 'example.org')]:
            bad = dict(good, **{key: value})
            with self.assertRaises(ValueError):
                check_inventory(bad)

    def test_saved_synthetic_replay_contract(self):
        fixtures = Path(__file__).parent / 'fixtures/soc/synthetic-events.jsonl'
        for line in fixtures.read_text().splitlines():
            row = json.loads(line)
            self.assertTrue(row['synthetic'])
            self.assertEqual(matches(row['event']), row['expected'])

    def test_compose_exposure_and_resource_guards(self):
        ports = {'manager': ['192.168.77.1:1514:1514', '127.0.0.1:55000:55000'],
                 'indexer': ['127.0.0.1:19200:9200'], 'dashboard': ['127.0.0.1:8443:5601']}
        good = {'name': 'soc-lab', 'networks': copy.deepcopy(NETWORK),
                'services': {f'wazuh.{name}': {'image': f'wazuh/wazuh-{name}:{VERSION}', 'ports': binding,
                    'restart': 'no', 'cpus': 0.5, 'mem_limit': '768m'} for name, binding in ports.items()}}
        validate_deployment(good)
        for change in ({'ports': ['0.0.0.0:1514:1514']}, {'privileged': True}, {'network_mode': 'host'},
                       {'volumes': ['/var/run/docker.sock:/var/run/docker.sock:ro']},
                       {'cpus': 8}, {'restart': 'always'}, {'image': 'wazuh/wazuh-manager:latest'}):
            bad = copy.deepcopy(good)
            bad['services']['wazuh.manager'].update(change)
            with self.assertRaises(ValueError): validate_deployment(bad)
        bad = copy.deepcopy(good)
        bad['networks']['default']['ipam']['config'][0]['subnet'] = '0.0.0.0/0'
        with self.assertRaises(ValueError): validate_deployment(bad)

    def test_homelab_log_source_identity(self):
        good = {'Config': {'Labels': {'com.docker.compose.project': 'it-support-homelab',
            'com.docker.compose.service': 'directory', 'com.docker.compose.project.working_dir': r'H:\My Projects - IT\it-support-homelab'}},
            'NetworkSettings': {'Networks': {'office-lan': {'IPAddress': '172.20.0.2'}}}}
        validate_container(good, 'directory')
        for key, value in [('com.docker.compose.project', 'third-party'),
                           ('com.docker.compose.service', 'other'), ('com.docker.compose.project.working_dir', r'C:\other')]:
            bad = copy.deepcopy(good)
            bad['Config']['Labels'][key] = value
            with self.assertRaises(ValueError): validate_container(bad, 'directory')
        bad = copy.deepcopy(good)
        bad['NetworkSettings']['Networks']['office-lan']['IPAddress'] = '8.8.8.8'
        with self.assertRaises(ValueError): validate_container(bad, 'directory')

    def test_publication_redacts_transport_tokens_and_keeps_identity(self):
        token = 'AB' + 'c' * 24 + '=='
        command = 'powershell.exe -V2SocketServerMode -Token ' + token + ' -UTCTimestamp example'
        source = {'id': 'real-record-identity', 'data': {'parentCommandLine': command},
                  'full_log': json.dumps({'parentCommandLine': command}), 'xml': '<Data>' + command + '</Data>'}
        public = redact_public(source)
        self.assertEqual(public['id'], source['id'])
        self.assertNotIn(token, json.dumps(public))
        self.assertIn('[REDACTED_SESSION_TOKEN]', public['data']['parentCommandLine'])
        self.assertIn(token, source['data']['parentCommandLine'])


if __name__ == '__main__':
    unittest.main()
