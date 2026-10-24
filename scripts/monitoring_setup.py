"""Prepare a private, pinned Wazuh single-node stack. No arbitrary targets.

Setup downloads are official software acquisition, never target testing.
The generated Compose network is a dedicated private bridge; only exact lab
ingress and loopback administration are published. The source firewall comes first.
"""
from pathlib import Path
import argparse
import json
import secrets
import shutil
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / 'private/monitoring'
UPSTREAM = ROOT / 'private/wazuh-upstream'
VERSION = '4.14.9'
COMMIT = '56ece955b1107b7b62823afae5b7057e1dab9d98'
NETWORK = {'default': {'name': 'soc-lab-private', 'driver': 'bridge', 'enable_ipv6': False,
                        'ipam': {'config': [{'subnet': '172.29.77.0/24'}]}}}


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def check_inventory(inventory):
    import ipaddress
    if inventory.get('DC01') != '192.168.77.10' or inventory.get('switch') != 'WindowsADLab-Internal' or inventory.get('domain') != 'corp.lab':
        raise ValueError('Owned VM inventory mismatch')
    client = ipaddress.ip_address(inventory['CLIENT01'])
    if client.version != 4 or not ipaddress.ip_address('192.168.77.100') <= client <= ipaddress.ip_address('192.168.77.150'):
        raise ValueError('Client outside owned DHCP range')


def validate_deployment(config, bootstrap=False):
    expected = {'wazuh.manager': ['192.168.77.1:1514:1514', '127.0.0.1:55000:55000'],
                'wazuh.indexer': ['127.0.0.1:19200:9200'], 'wazuh.dashboard': ['127.0.0.1:8443:5601']}
    if bootstrap:
        expected['wazuh.manager'][0] = '127.0.0.1:1514:1514'
    if config.get('name') != 'soc-lab' or set(config['services']) != set(expected):
        raise ValueError('Unexpected SIEM project/service')
    if config.get('networks') != NETWORK:
        raise ValueError('SIEM must use its dedicated pinned private bridge')
    for name, service in config['services'].items():
        if service['ports'] != expected[name] or service['image'] != f'wazuh/wazuh-{name.split(".")[1]}:{VERSION}':
            raise ValueError('Unexpected image or exposed address/port')
        if service.get('privileged') or service.get('network_mode') or service.get('cap_add'):
            raise ValueError('Privileged/host networking is forbidden')
        if any('docker.sock' in str(volume) or 'docker_engine' in str(volume) for volume in service.get('volumes', [])):
            raise ValueError('Docker control socket must not be mounted')
        if service.get('restart') != 'no' or not service.get('mem_limit') or float(service.get('cpus', 99)) > 1:
            raise ValueError('Explicit low-pressure resource limits required')


def prepare():
    import bcrypt
    import yaml
    PRIVATE.mkdir(parents=True, exist_ok=True)
    if not UPSTREAM.exists():
        run('git', 'clone', '--depth', '1', '--branch', f'v{VERSION}',
            'https://github.com/wazuh/wazuh-docker.git', str(UPSTREAM))
    actual = run('git', '-C', str(UPSTREAM), 'rev-parse', 'HEAD', capture_output=True).stdout.strip()
    if actual != COMMIT:
        raise ValueError('Upstream revision differs from reviewed version')
    destination = PRIVATE / 'stack'
    if destination.exists():
        raise ValueError('Private stack already exists; refusing credential rotation or overwrite')
    # Generate credentials once; never echo values, pass them on a CLI, or commit them.
    env = ROOT / '.env'
    if env.exists():
        raise ValueError('Existing .env: merge credentials manually before preparing stack')
    shutil.copytree(UPSTREAM / 'single-node', destination)
    passwords = {key: 'Aa1!' + secrets.token_hex(22) for key in
                 ('INDEXER_PASSWORD', 'DASHBOARD_PASSWORD', 'API_PASSWORD', 'LAB_ACCOUNT_PASSWORD')}
    env.write_text(''.join(f'{k}={v}\n' for k, v in passwords.items()), encoding='utf-8')
    config = destination / 'config'
    users = {'_meta': {'type': 'internalusers', 'config_version': 2}}
    for user, key in [('admin', 'INDEXER_PASSWORD'), ('kibanaserver', 'DASHBOARD_PASSWORD')]:
        users[user] = {'hash': bcrypt.hashpw(passwords[key].encode(), bcrypt.gensalt()).decode(), 'reserved': True}
        if user == 'admin':
            users[user]['backend_roles'] = ['admin']
    (config / 'wazuh_indexer/internal_users.yml').write_text(yaml.safe_dump(users))
    dashboard = yaml.safe_load((config / 'wazuh_dashboard/wazuh.yml').read_text())
    dashboard['hosts'][0][1513629884013]['password'] = passwords['API_PASSWORD']
    (config / 'wazuh_dashboard/wazuh.yml').write_text(yaml.safe_dump(dashboard))
    text = (config / 'wazuh_cluster/wazuh_manager.conf').read_text()
    wrapper = ET.fromstring('<root>' + text + '</root>')
    primary = wrapper.find('ossec_config')
    primary.find('global/logall_json').text = 'yes'
    primary.find('auth/disabled').text = 'yes'  # Explicit key enrolment only; no open authd.
    primary.find('vulnerability-detection/enabled').text = 'no'  # Internal network, no feed egress.
    primary.find('cluster/key').text = secrets.token_hex(16)
    for tag in ('rootcheck', 'syscheck'):
        primary.find(tag + '/disabled').text = 'yes'
    primary.find('sca/enabled').text = 'no'
    ET.SubElement(ET.SubElement(primary, 'active-response'), 'disabled').text = 'yes'
    for service in ('directory', 'fileserver', 'wireguard', 'printserver'):
        lf = ET.SubElement(primary, 'localfile')
        ET.SubElement(lf, 'location').text = f'/lab-logs/{service}.log'
        ET.SubElement(lf, 'log_format').text = 'syslog'
    (config / 'wazuh_cluster/wazuh_manager.conf').write_text(''.join(ET.tostring(c, encoding='unicode') for c in wrapper))
    compose = yaml.safe_load((destination / 'docker-compose.yml').read_text())
    compose['name'] = 'soc-lab'
    compose['networks'] = NETWORK
    bindings = {'wazuh.manager': ['192.168.77.1:1514:1514', '127.0.0.1:55000:55000'],
                'wazuh.indexer': ['127.0.0.1:19200:9200'], 'wazuh.dashboard': ['127.0.0.1:8443:5601']}
    limits = {'wazuh.manager': ('768m', 0.75), 'wazuh.indexer': ('1536m', 0.75),
              'wazuh.dashboard': ('768m', 0.5)}
    for name, service in compose['services'].items():
        service['ports'] = bindings[name]
        service['restart'] = 'no'  # Explicit lab sessions only, never auto-start on login.
        service['mem_limit'], service['cpus'] = limits[name]
        service['logging'] = {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '2'}}
        service['environment'] = {key: value.strip('"') for key, value in
                                  (entry.split('=', 1) for entry in service.get('environment', []))}
        for key in passwords:
            if key in service['environment']:
                service['environment'][key] = '${' + key + ':?Set in ignored .env}'
        if name == 'wazuh.indexer':
            service['environment']['OPENSEARCH_JAVA_OPTS'] = '-Xms512m -Xmx512m'
    logs = PRIVATE / 'container-logs'
    logs.mkdir(exist_ok=True)
    for service in ('directory', 'fileserver', 'wireguard', 'printserver'):
        (logs / f'{service}.log').touch()
    manager = compose['services']['wazuh.manager']
    manager['volumes'] += [str(ROOT / 'monitoring/local_rules.xml').replace('\\', '/') + ':/var/ossec/etc/rules/soc_lab.xml:ro',
                           str(logs).replace('\\', '/') + ':/lab-logs:ro']
    (destination / 'compose.json').write_text(json.dumps(compose, indent=2))
    manager_only = json.loads(json.dumps(compose))
    manager_only['services']['wazuh.manager']['ports'] = ['127.0.0.1:1514:1514', '127.0.0.1:55000:55000']
    (destination / 'bootstrap.json').write_text(json.dumps(manager_only, indent=2))
    (PRIVATE / 'provenance.json').write_text(json.dumps({'version': VERSION, 'upstream_commit': actual,
        'upstream_license': 'GPL-2.0', 'deployment': 'generated from official single-node; private configuration'}, indent=2))
    print('Private configuration prepared. Credentials are in ignored .env. Run host Enroll network preflight before deploy.')


def compose(*args, capture_output=False):
    return run('docker', 'compose', '--env-file', str(ROOT / '.env'), '-f', str(PRIVATE / 'stack/compose.json'),
               *args, capture_output=capture_output)


def deploy():
    validate_deployment(json.loads((PRIVATE / 'stack/compose.json').read_text()))
    check_inventory(json.loads((PRIVATE / 'inventory.json').read_text(encoding='utf-8-sig')))
    # Network guard must precede published manager ingress.
    guard = json.loads((PRIVATE / 'Firewall-result.json').read_text(encoding='utf-8-sig'))
    if not guard['success']:
        raise ValueError('Host firewall not established')
    run('docker', 'compose', '-p', 'soc-certs', '-f', str(PRIVATE / 'stack/generate-indexer-certs.yml'), 'run', '--rm', 'generator')
    compose('up', '-d')


def bootstrap():
    """Manager only, loopback only, for key generation before guest setup."""
    config = PRIVATE / 'stack/bootstrap.json'
    validate_deployment(json.loads(config.read_text()), bootstrap=True)
    if not (PRIVATE / 'stack/config/wazuh_indexer_ssl_certs/root-ca.pem').exists():
        run('docker', 'compose', '-p', 'soc-certs', '-f', str(PRIVATE / 'stack/generate-indexer-certs.yml'), 'run', '--rm', 'generator')
    run('docker', 'compose', '--env-file', str(ROOT / '.env'), '-f', str(config), 'up', '-d', '--no-deps', 'wazuh.manager')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['prepare', 'bootstrap', 'deploy', 'status', 'stop'])
    args = p.parse_args()
    if args.action == 'prepare': prepare()
    elif args.action == 'bootstrap': bootstrap()
    elif args.action == 'deploy': deploy()
    elif args.action == 'status': compose('ps')
    elif args.action == 'stop': compose('stop')
