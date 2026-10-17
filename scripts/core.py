"""Pure parsing, strict scope validation and findings synthesis (no network)."""
import ipaddress
import json
import xml.etree.ElementTree as ET

SERVICES = frozenset({'wireguard', 'fileserver', 'printserver', 'uptime', 'directory'})
SUBNET = ipaddress.ip_network('172.20.0.0/16')
HOST_PORTS = (1445, 1389, 1636, 51821, 13001, 6631)


def validate_scope(records, members):
    """Trust only current Compose project labels AND membership in office-lan.

    A private address alone never authorizes a target. No arbitrary CIDR scans.
    """
    result = {}
    for item in records:
        labels = item['Config']['Labels']
        service = labels.get('com.docker.compose.service')
        if labels.get('com.docker.compose.project') != 'it-support-homelab':
            raise ValueError('Unexpected Compose project')
        # Supporting services (including the TLS proxy) cannot widen host exposure.
        for binding in (item['NetworkSettings'].get('Ports') or {}).values():
            for endpoint in binding or []:
                if endpoint['HostIp'] != '127.0.0.1':
                    raise ValueError('Host publication is not loopback-only')
        if service not in SERVICES:
            continue
        if not item['State']['Running'] or item['Id'] not in members:
            raise ValueError('Lab container not running on office-lan')
        address = item['NetworkSettings']['Networks']['office-lan']['IPAddress']
        if ipaddress.ip_address(address) not in SUBNET:
            raise ValueError('Lab address outside pinned subnet')
        if service in result or address in result.values():
            raise ValueError('Ambiguous lab identity')
        result[service] = address
    if set(result) != SERVICES:
        raise ValueError('All five homelab targets must be present')
    return result


def validate_target(target, scope):
    if target not in scope and target not in scope.values() and target != '127.0.0.1':
        raise ValueError('REFUSED: target is not an allow-listed lab host')
    return scope.get(target, target)


def parse_nmap(text, scope):
    root = ET.fromstring(text)
    hosts = []
    for host in root.findall('host'):
        address = host.find('address').get('addr')
        validate_target(address, scope)
        if host.find('status').get('state') != 'up':
            continue
        asset = next((k for k, v in scope.items() if v == address), 'host-loopback')
        ports = []
        for port in host.findall('ports/port'):
            if port.find('state').get('state') != 'open':
                continue
            svc = port.find('service')
            ports.append({'port': int(port.get('portid')), 'protocol': port.get('protocol'),
                          'service': svc.get('name', '') if svc is not None else '',
                          'version': ' '.join(svc.get(k, '') for k in ('product', 'version', 'extrainfo')).strip() if svc is not None else '',
                          'scripts': {s.get('id'): s.get('output') for s in port.findall('script')}})
        hosts.append({'asset': asset, 'address': address, 'ports': ports,
                      'scripts': {s.get('id'): s.get('output') for s in host.findall('hostscript/script')}})
    return hosts


def parse_nuclei(text, scope):
    from urllib.parse import urlsplit
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        host = urlsplit(item.get('matched-at', item.get('host', ''))).hostname
        validate_target(host, scope)
        info = item['info']
        rows.append({'template': item['template-id'], 'name': info['name'],
                     'severity': info['severity'], 'asset': host,
                     'matched': item.get('matched-at'), 'classification': info.get('classification', {})})
    return rows


CATALOG = [
    {'id': 'SAL-01', 'asset': 'fileserver / SMB 445', 'severity': 'Medium',
     'title': 'SMB signing is optional', 'control': 'smb_signing_required',
     'risk': 'A malicious peer on office-lan could tamper with unsigned SMB sessions or participate in relay attacks. Requires access to this local lab network; no internet exposure was observed.',
     'remediation': 'Set server signing = mandatory in the persistent fileserver Compose command; recreate the service and require signed client sessions.',
     'verification': 'Compare the baseline Nmap smb2-security-mode (enabled but not required) with a direct SMB2 NEGOTIATE response on host loopback 1445 and the retest Nmap output (required). Confirm alice can still list Finance with signing required. In this Samba client, signing=disabled remains a preference and does not force an unsigned session when the server requires signing; its exit code is not a closure criterion.',
     'rating': 'CVSS-style qualitative Medium: adjacent-network prerequisite, potential confidentiality/integrity impact. No exploit chain or numeric CVSS score asserted.'},
    {'id': 'SAL-02', 'asset': 'directory / ITOPS.LAB', 'severity': 'Low',
     'title': 'Zero minimum password age permits rapid password changes', 'control': 'ad_min_age',
     'risk': 'An authenticated fictional user can change passwords repeatedly, reducing the value of the 12-password history. No weak password or completed history bypass is claimed.',
     'remediation': 'Set minimum password age to one day in seed.sh and the running directory; preserve administrative password-reset workflows.',
     'verification': 'Create one temporary fictional assessment_probe account with random strong passwords. Perform two self-service changes, then remove the account in finally. Retest must reject an immediate self-service change.',
     'rating': 'CVSS-style qualitative Low: requires a valid local domain account; policy weakness without demonstrated compromise.'},
    {'id': 'SAL-03', 'asset': 'wg-easy, Uptime Kuma, CUPS / host loopback', 'severity': 'Low',
     'title': 'Administration uses plaintext HTTP', 'control': 'admin_tls',
     'risk': 'Admin sessions and CUPS Basic credentials lack transport encryption on the host-facing HTTP listeners. Loopback binding substantially reduces exposure; privileged host compromise is outside this proof.',
     'remediation': 'Terminate TLS with a local Caddy CA on the same loopback admin ports and remove direct HTTP host publications. Trust the exported public CA explicitly. Internal office-lan HTTP remains a documented residual risk.',
     'verification': 'Make credential-free HTTP requests to all three original ports before remediation, then verify HTTP no longer serves the application and HTTPS validates against the exported lab CA.',
     'rating': 'CVSS-style qualitative Low in this loopback-only deployment. Three endpoints are grouped under one root cause; not three inflated findings.'}
]


def findings(baseline, current):
    result = []
    for entry in CATALOG:
        key = entry['control']
        if baseline['controls'].get(key) is False:
            row = dict(entry)
            passed = current['controls'].get(key)
            row['status'] = 'Fixed - retested' if passed is True else 'Open' if passed is False else 'Not tested'
            row['evidence'] = [f"../evidence/{baseline['run_id']}/checks.json", f"../evidence/{current['run_id']}/checks.json"]
            result.append(row)
    return result
