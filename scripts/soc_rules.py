"""Offline field checks against the actual custom-rule XML, without a SIEM.

This deliberately supports only the small stateless XML subset used here. It is
not Wazuh's decoder or correlation engine. Live acceptance requires real alerts.
"""
from collections import Counter
from pathlib import Path
import json
import re
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / 'monitoring/local_rules.xml'
CATALOG = json.loads((ROOT / 'monitoring/detections.json').read_text())
ALIASES = {'110108': '110103'}


def field(event, name):
    for part in name.split('.'):
        if not isinstance(event, dict) or part not in event:
            return ''
        event = event[part]
    return str(event)


def parse_event_xml(text):
    """Normalize saved Get-WinEvent XML to Wazuh's lower-camel field names."""
    node = ET.fromstring(text)
    ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    system = node.find('e:System', ns)
    if system is None:
        raise ValueError('Missing event system')
    values = {}
    for source, target in [('EventID', 'eventID'), ('Computer', 'computer'),
                           ('Channel', 'channel'), ('Keywords', 'keywords'),
                           ('EventRecordID', 'eventRecordID')]:
        child = system.find('e:' + source, ns)
        values[target] = child.text if child is not None else ''
    provider = system.find('e:Provider', ns)
    values['providerName'] = provider.get('Name', '') if provider is not None else ''
    clock = system.find('e:TimeCreated', ns)
    values['systemTime'] = clock.get('SystemTime', '') if clock is not None else ''
    data = {}
    for item in node.findall('e:EventData/e:Data', ns):
        name = item.get('Name', '')
        if name:
            data[name[0].lower() + name[1:]] = item.text or ''
    return {'win': {'system': values, 'eventdata': data}}


def load_rules(path=RULES):
    root = ET.parse(path).getroot()
    rules = list(root.findall('rule'))
    ids = [r.get('id') for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate rule ID')
    supported = {'if_sid', 'if_group', 'field', 'description', 'mitre', 'group'}
    for rule in rules:
        if set(rule.attrib) != {'id', 'level'} or not 100000 <= int(rule.get('id')) <= 120000:
            raise ValueError('Unsupported rule attributes or custom ID')
        if any(child.tag not in supported for child in rule):
            raise ValueError('Unsupported rule semantics')
        for f in rule.findall('field'):
            if set(f.attrib) - {'name', 'type'} or f.get('type', 'osregex') not in {'pcre2', 'osregex'}:
                raise ValueError('Unsupported field semantics')
            re.compile(f.text)
    return rules


def matches(event, rules=None, before_tuning=False):
    rules = load_rules() if rules is None else rules
    # Model the field contract after EventChannel decoding. Never claim to test it.
    parents = {'60000'} if field(event, 'win.system.providerName') else set()
    result = []
    for rule in rules:
        if rule.find('if_group') is not None:
            if rule.findtext('if_group') != 'windows' or not parents:
                continue
        elif rule.findtext('if_sid') not in parents:
            continue
        fields = rule.findall('field')
        if before_tuning and rule.get('id') == '110107':
            fields = [f for f in fields if f.get('name') != 'win.system.keywords']
        if all(re.search(f.text, field(event, f.get('name'))) for f in fields):
            parents.add(rule.get('id'))
            if int(rule.get('level')) > 0:
                result.append(rule.get('id'))
    return result


def counts(events, before_tuning=False):
    return dict(Counter(r for event in events
                        for r in {ALIASES.get(hit, hit) for hit in matches(event, before_tuning=before_tuning)}))


def read_jsonl(path):
    return [json.loads(line) for line in Path(path).read_text(encoding='utf-8-sig').splitlines() if line.strip()]


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('events', type=Path)
    args = parser.parse_args()
    events = read_jsonl(args.events)
    events = [parse_event_xml(e['xml']) if 'xml' in e else e.get('data', e) for e in events]
    print(json.dumps({'kind': 'offline field replay, not live Wazuh acceptance',
                      'events': len(events), 'before': counts(events, True), 'after': counts(events)}, indent=2))
