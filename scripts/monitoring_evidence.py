"""Verify captured SOC evidence, replay saved fields and report only observed counts."""
from collections import Counter
from pathlib import Path
import argparse
import hashlib
import json

from soc_rules import ALIASES, CATALOG, RULES, counts, field, matches, parse_event_xml, read_jsonl

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'evidence/monitoring'


def verify(folder=EVIDENCE):
    manifest = folder / 'manifest.json'
    if not manifest.exists():
        print('SOC live evidence pending; no live coverage claimed.')
        return
    metadata = json.loads(manifest.read_text())
    if metadata.get('kind') != 'captured lab evidence':
        raise ValueError('Manifest must identify captured evidence')
    for name, expected in metadata['sha256'].items():
        path = (folder / name).resolve()
        if not path.is_relative_to(folder.resolve()):
            raise ValueError('Evidence path escapes folder')
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f'Evidence hash differs: {name}')
    alerts = read_jsonl(folder / 'alerts.jsonl')
    source = [parse_event_xml(row['xml']) for row in read_jsonl(folder / 'windows-events.jsonl')]
    records = {(field(event,'win.system.computer').lower(),field(event,'win.system.eventRecordID')) for event in source}
    seen = set()
    by_rule = Counter()
    for alert in alerts:
        if alert['agent']['name'] not in ('DC01', 'CLIENT01') or not alert.get('timestamp') or not alert.get('id'):
            raise ValueError('Missing alert identity or unowned endpoint')
        if alert['id'] in seen:
            raise ValueError('Duplicate alert')
        seen.add(alert['id'])
        rule = str(alert['rule']['id'])
        if alert.get('decoder', {}).get('name') != 'windows_eventchannel':
            raise ValueError('Acceptance requires native EventChannel alerts')
        data = alert['data']
        computer = field(data, 'win.system.computer')
        if computer.split('.')[0].upper() != alert['agent']['name'] or (computer.lower(),field(data,'win.system.eventRecordID')) not in records:
            raise ValueError('Alert source does not match the captured Windows record')
        if rule.startswith('1101') and rule not in matches(alert['data']):
            raise ValueError(f'Saved alert no longer matches current field contract: {rule}')
        by_rule[ALIASES.get(rule, rule)] += 1
    if set(by_rule) != {row['rule'] for row in CATALOG}:
        raise ValueError('Native detection coverage incomplete')
    metrics = json.loads((folder / 'metrics.json').read_text())
    if metrics['per_detection'] != dict(by_rule) or metrics['total_detection_alerts'] != len(alerts):
        raise ValueError('Metrics do not reconcile with actual alerts')
    tuning = json.loads((folder / 'engine-tuning.json').read_text())
    shares = [event for event in source if field(event,'win.system.eventID') == '5145'
              and field(event,'win.eventdata.shareName').lower().endswith('\\socrestricted')]
    if tuning['input_events'] != len(shares) or tuning['before_alerts'] != counts(shares, True)['110107'] or tuning['after_alerts'] != counts(shares)['110107']:
        raise ValueError('Tuning counts differ from the saved real share records')
    if tuning.get('current_rules_lf_sha256') != hashlib.sha256(RULES.read_bytes().replace(b'\r\n',b'\n')).hexdigest():
        raise ValueError('Rule XML changed after the recorded engine replay')
    print(json.dumps({'captured_alerts': len(alerts), 'per_rule': dict(by_rule)}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder', type=Path, default=EVIDENCE)
    verify(parser.parse_args().folder)
