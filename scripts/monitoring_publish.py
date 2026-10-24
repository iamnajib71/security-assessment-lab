"""Publish reviewed native lab alerts and matching source events, never fixtures.

Call only after reviewing private inputs. All outputs are credential checked by
check_secrets.py before commit. Saved replay results must identify their method.
"""
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import re
import shutil

from soc_rules import ALIASES, CATALOG, ROOT, field, matches, parse_event_xml, read_jsonl

PRIVATE = ROOT / 'private/monitoring'
OUT = ROOT / 'evidence/monitoring'


def redact_public(value):
    """Keep real event identity/content, removing only transport authentication."""
    if isinstance(value, dict): return {key: redact_public(item) for key, item in value.items()}
    if isinstance(value, list): return [redact_public(item) for item in value]
    if isinstance(value, str):
        return re.sub(r'(?i)(-Token\s+)[A-Za-z0-9+/=_-]+', r'\1[REDACTED_SESSION_TOKEN]', value)
    return value


def write_json(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def main():
    OUT.mkdir(exist_ok=True, parents=True)
    wanted = {row['rule'] for row in CATALOG} | set(ALIASES)
    all_alerts = read_jsonl(PRIVATE / 'manager-alerts.jsonl')
    alerts = [row for row in all_alerts if str(row.get('rule', {}).get('id')) in wanted]
    if any(row['agent']['name'] not in ('DC01', 'CLIENT01') for row in alerts):
        raise ValueError('Unowned alert')
    coverage = {ALIASES.get(str(row['rule']['id']), str(row['rule']['id'])) for row in alerts}
    if coverage != {row['rule'] for row in CATALOG}:
        raise ValueError(f'Native detection acceptance incomplete: {sorted(coverage)}')
    for alert in alerts:
        if str(alert['rule']['id']) not in matches(alert['data']):
            raise ValueError('Captured native alert differs from current condition')
    (OUT / 'alerts.jsonl').write_text(''.join(json.dumps(redact_public(row), ensure_ascii=False) + '\n' for row in alerts), encoding='utf-8')
    source = []
    for name in ('DC01', 'CLIENT01'):
        sysmon_saved = False
        for row in read_jsonl(PRIVATE / f'{name}-events.jsonl'):
            event = parse_event_xml(row['xml'])
            ident = field(event, 'win.system.eventID')
            keep = bool(set(matches(event)) & wanted)
            keep |= ident == '5145' and field(event, 'win.eventdata.shareName').lower().endswith('\\socrestricted')
            keep |= ident == '4625' and field(event, 'win.eventdata.targetUserName').lower() in ('soc.lockout', 'alex.morgan')
            if not sysmon_saved and field(event, 'win.system.channel') == 'Microsoft-Windows-Sysmon/Operational' and ident == '1':
                keep = sysmon_saved = True
            if keep: source.append(row)
    (OUT / 'windows-events.jsonl').write_text(''.join(json.dumps(redact_public(row), ensure_ascii=False) + '\n' for row in source), encoding='utf-8')
    contexts = []
    for name in ('DC01', 'CLIENT01'):
        candidates = [row for row in all_alerts if row.get('agent', {}).get('name') == name
                      and str(row.get('rule', {}).get('id')) == '110109'
                      and field(row.get('data', {}), 'win.system.eventID') == '1']
        if not candidates: raise ValueError(f'No native Sysmon process event for {name}')
        contexts.append(candidates[0])
    (OUT / 'sysmon-context.jsonl').write_text(''.join(json.dumps(redact_public(row), ensure_ascii=False) + '\n' for row in contexts), encoding='utf-8')
    for name in ('account-state.json', 'lockout-policy.json', 'DC01-enrollment.json', 'CLIENT01-enrollment.json',
                 'DC01-cleanup-checks.json', 'CLIENT01-cleanup-checks.json'):
        shutil.copyfile(PRIVATE / name, OUT / name)
    counts = Counter(ALIASES.get(str(row['rule']['id']), str(row['rule']['id'])) for row in alerts)
    metrics = {'kind': 'native Wazuh alerts', 'total_detection_alerts': len(alerts), 'per_detection': dict(counts),
               'first_ingestion': min(row['timestamp'] for row in alerts), 'last_ingestion': max(row['timestamp'] for row in alerts),
               'distinct_detections': len(coverage), 'sysmon_context_samples': len(contexts),
               'note': 'Repeated approved validation changes can create multiple alerts; these are not distinct attacks.'}
    write_json('metrics.json', metrics)
    write_json('provenance.json', {'kind': 'captured lab evidence', 'packaged_at': datetime.now(timezone.utc).isoformat(),
        'collection': 'Native Windows Wazuh EventChannel agents; buffered while manager stopped to reduce memory pressure',
        'source_clock': 'Windows systemTime in each XML; timestamps in alerts are ingestion times',
        'lockout_method': 'Owner-authorised Hyper-V console keyboard input; fixed deliberately wrong value; five capped submissions; no password search',
        'lockout_caller_field': 'Microsoft event 4740 TargetDomainName is the caller computer in this event schema',
        'console_note': 'One earlier blank attempt on fictional alex.morgan during navigation; account remained enabled and unlocked; recorded account state retained',
        'synthetic_inputs': False,
        'public_redactions': 'PowerShell Direct -Token transport authentication values removed from Sysmon parent command lines; original captures retained privately. Alert IDs, source record IDs, timestamps and detection fields are unchanged.'})
    for name in ('engine-tuning.json', 'engine-before.txt', 'engine-after.txt', 'rules-before-tuning.xml'):
        if (PRIVATE / name).exists(): shutil.copyfile(PRIVATE / name, OUT / name)
    manifest = {'kind': 'captured lab evidence', 'sha256': {}}
    for path in sorted(OUT.iterdir()):
        if path.is_file() and path.name not in ('manifest.json', 'README.md'):
            manifest['sha256'][path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    write_json('manifest.json', manifest)
    print(json.dumps(metrics, indent=2))


if __name__ == '__main__': main()
