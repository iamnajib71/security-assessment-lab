"""Generate importable Wazuh/OpenSearch saved objects; no fabricated display data."""
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]


def saved_objects():
    index = 'soc-lab-alerts'
    query = {'query': 'rule.groups: soc_lab and not rule.id: 110109', 'language': 'kuery'}
    search = json.dumps({'query': query, 'filter': []})
    fields = [{'name': name, 'type': typ, 'searchable': True, 'aggregatable': True,
               'readFromDocValues': True, 'esTypes': ['date' if typ == 'date' else 'keyword']}
              for name, typ in [('timestamp', 'date'), ('rule.id', 'string'), ('rule.mitre.id', 'string'), ('agent.name', 'string')]]
    catalog = json.loads((ROOT / 'monitoring/detections.json').read_text())
    mapping = {row['rule']: row['technique'] for row in catalog}
    mapping['110108'] = 'T1078'
    script = "if (doc.containsKey('rule.id') && doc['rule.id'].size() > 0) { String id = doc['rule.id'].value.toString(); "
    script += ' '.join(f"if (id == '{rule}') return '{technique}';" for rule, technique in mapping.items())
    script += " } return '';"
    fields.append({'name': 'soc_lab_technique', 'type': 'string', 'scripted': True, 'script': script,
                   'lang': 'painless', 'searchable': False, 'aggregatable': True, 'readFromDocValues': False})
    labels = {'agent.name':'Endpoint','rule.id':'Rule ID','soc_lab_technique':'ATT&CK technique',
              'data.win.system.eventID':'Event ID','data.win.eventdata.targetUserName':'Account',
              'data.win.eventdata.targetDomainName':'Caller (4740)'}
    for name in ('data.win.system.eventID','data.win.eventdata.targetUserName','data.win.eventdata.targetDomainName'):
        fields.append({'name':name,'type':'string','searchable':True,'aggregatable':False,'readFromDocValues':False,'esTypes':['keyword']})
    objects = [{'type': 'index-pattern', 'id': index, 'attributes': {'title': 'wazuh-alerts-*', 'timeFieldName': 'timestamp', 'fields': json.dumps(fields)}}]
    objects[0]['attributes']['fieldAttrs'] = json.dumps({name:{'customLabel':label} for name,label in labels.items()})
    panels = []
    specs = [('soc-count', 'Lab alerts', 'metric', [{'id': '1', 'enabled': True, 'type': 'count', 'schema': 'metric', 'params': {}}]),
             ('soc-rules', 'Alerts by rule', 'table', [{'id': '1', 'enabled': True, 'type': 'count', 'schema': 'metric', 'params': {}},
                {'id': '2', 'enabled': True, 'type': 'terms', 'schema': 'bucket', 'params': {'field': 'rule.id', 'size': 20, 'order': 'desc', 'orderBy': '1'}}]),
             ('soc-techniques', 'ATT&CK mapping from rule catalog', 'table', [{'id': '1', 'enabled': True, 'type': 'count', 'schema': 'metric', 'params': {}},
                {'id': '2', 'enabled': True, 'type': 'terms', 'schema': 'bucket', 'params': {'field': 'soc_lab_technique', 'size': 20, 'order': 'desc', 'orderBy': '1'}}]),
             ('soc-hosts', 'Alerts by enrolled endpoint', 'pie', [{'id': '1', 'enabled': True, 'type': 'count', 'schema': 'metric', 'params': {}},
                {'id': '2', 'enabled': True, 'type': 'terms', 'schema': 'segment', 'params': {'field': 'agent.name', 'size': 10, 'order': 'desc', 'orderBy': '1'}}])]
    for position, (ident, title, typ, aggs) in enumerate(specs):
        source = json.loads(search)
        source['indexRefName'] = 'kibanaSavedObjectMeta.searchSourceJSON.index'
        objects.append({'type': 'visualization', 'id': ident, 'attributes': {'title': title,
            'visState': json.dumps({'title': title, 'type': typ, 'params': {}, 'aggs': aggs}),
            'uiStateJSON': '{}', 'description': 'Actual indexed Wazuh alerts only; fictional lab actions.',
            'kibanaSavedObjectMeta': {'searchSourceJSON': json.dumps(source)}},
            'references': [{'name': 'kibanaSavedObjectMeta.searchSourceJSON.index', 'type': 'index-pattern', 'id': index}]})
        panels.append({'panelIndex': str(position + 1), 'type': 'visualization', 'panelRefName': ident, 'version': '7.10.2',
                       'embeddableConfig': {}, 'gridData': {'x': (position % 2) * 24, 'y': (position // 2) * 16, 'w': 24, 'h': 16, 'i': str(position + 1)}})
    objects.append({'type': 'dashboard', 'id': 'soc-lab-triage', 'attributes': {'title': 'Owned lab — monitoring and triage',
        'description': 'Benign administrative exercises. Alert counts are not confirmed attacks.', 'hits': 0, 'version': 1,
        'panelsJSON': json.dumps(panels), 'optionsJSON': json.dumps({'useMargins': True, 'hidePanelTitles': False}),
        'timeRestore': True, 'timeFrom': 'now-24h', 'timeTo': 'now',
        'kibanaSavedObjectMeta': {'searchSourceJSON': search}},
        'references': [{'name': ident, 'type': 'visualization', 'id': ident} for ident, *_ in specs]})
    return objects


if __name__ == '__main__':
    target = ROOT / 'monitoring/dashboards.ndjson'
    target.write_text('\n'.join(json.dumps(obj, ensure_ascii=False) for obj in saved_objects()) + '\n', encoding='utf-8')
    print(f'{len(saved_objects())} saved objects written; no example alerts or screenshots generated')
