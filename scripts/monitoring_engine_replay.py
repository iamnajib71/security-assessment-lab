"""Replay captured fields with Wazuh, using a temporary JSON-to-Windows bridge.

This tests Wazuh rule conditions after decoding, not EventChannel decoding.
Native-agent acceptance is measured separately from real alerts. Run only with
both Windows guests saved and no exercises in progress. No events are ingested
as production alerts. The live XML is restored in finally.
"""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import xml.etree.ElementTree as ET

from soc_rules import ROOT, RULES, field, parse_event_xml, read_jsonl

PRIVATE = ROOT / 'private/monitoring'
CONTAINER = 'soc-lab-wazuh.manager-1'
BRIDGE_PATH = '/var/ossec/etc/rules/soc_replay_bridge.xml'


def docker(*args, **kwargs):
    return subprocess.run(['docker', *args], check=True, text=True, capture_output=True, **kwargs)


def replay(events, label):
    result = docker('exec', '-i', CONTAINER, '/var/ossec/bin/wazuh-logtest',
                    input='\n'.join(json.dumps(event) for event in events) + '\n')
    output = result.stdout + result.stderr
    (PRIVATE / f'engine-{label}.txt').write_text(output, encoding='utf-8')
    return len(re.findall(r"^\s*id:\s*'110107'\s*$", output, re.M))


def main():
    events = [parse_event_xml(row['xml']) for row in read_jsonl(PRIVATE / 'DC01-events.jsonl')]
    events = [event for event in events if field(event, 'win.system.eventID') == '5145'
              and field(event, 'win.eventdata.shareName').lower().endswith('\\socrestricted')]
    if not events or not any(field(e, 'win.system.keywords').lower() == '0x8010000000000000' for e in events):
        raise ValueError('Real successful and denied share events are required')
    bridge_text = '<rule id="110000" level="0"><decoded_as>json</decoded_as>'
    bridge_text += (
        '<field name="win.system.providerName" type="pcre2">.+</field>'
        '<description>Temporary saved-field replay bridge; never native acceptance</description>'
        '<group>windows,</group></rule>')
    original = RULES.read_bytes()
    before = ET.fromstring(original)
    for rule in before.findall('rule'):
        if rule.get('id') == '110107':
            for condition in rule.findall('field'):
                if condition.get('name') == 'win.system.keywords': rule.remove(condition)
    before_bytes = ET.tostring(before, encoding='utf-8')
    def with_bridge(content):
        root = ET.fromstring(content)
        root.insert(0, ET.fromstring(bridge_text))
        return ET.tostring(root, encoding='utf-8')
    try:
        # Wazuh resolves group linkage in load order: bridge must precede rules.
        RULES.write_bytes(with_bridge(before_bytes))
        before_count = replay(events, 'before')
        RULES.write_bytes(with_bridge(original))
        after_count = replay(events, 'after')
        result = {'method': 'Wazuh logtest / temporary JSON group bridge / captured Windows fields',
                  'native_agent_acceptance': False, 'input_events': len(events),
                  'before_alerts': before_count, 'after_alerts': after_count,
                  'successful_events': sum(field(e, 'win.system.keywords').lower() == '0x8020000000000000' for e in events),
                  'denied_events': sum(field(e, 'win.system.keywords').lower() == '0x8010000000000000' for e in events),
                  'current_rules_sha256': hashlib.sha256(original).hexdigest(),
                  'before_rules_sha256': hashlib.sha256(before_bytes).hexdigest()}
        (PRIVATE / 'engine-tuning.json').write_text(json.dumps(result, indent=2))
        (PRIVATE / 'rules-before-tuning.xml').write_bytes(before_bytes)
        print(json.dumps(result, indent=2))
        if before_count != len(events) or after_count != result['denied_events']:
            raise ValueError('Wazuh engine result differs from expected success/failure conditions; inspect outputs')
    finally:
        RULES.write_bytes(original)
        docker('exec', CONTAINER, 'rm', '-f', BRIDGE_PATH)


if __name__ == '__main__': main()
