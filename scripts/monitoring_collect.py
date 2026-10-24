"""Collect only four verified owned Compose services; never mount Docker's socket."""
from datetime import datetime, timezone
from pathlib import Path
import argparse
import json
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ('directory', 'fileserver', 'wireguard', 'printserver')
LAB = r'H:\My Projects - IT\it-support-homelab'


def docker(*args):
    return subprocess.run(['docker', *args], capture_output=True, text=True, check=True)


def validate_container(record, service):
    labels = record['Config']['Labels']
    if service not in SERVICES or labels.get('com.docker.compose.project') != 'it-support-homelab' or labels.get('com.docker.compose.service') != service:
        raise ValueError('Unexpected Compose identity')
    directory = labels.get('com.docker.compose.project.working_dir', '').replace('\\', '/').lower().rstrip('/')
    # Docker Desktop labels retain the Windows path in this lab.
    if directory != LAB.replace('\\', '/').lower():
        raise ValueError('Container not created by the pinned owned lab')
    if 'office-lan' not in record['NetworkSettings']['Networks']:
        raise ValueError('Container outside office-lan')
    import ipaddress
    address = record['NetworkSettings']['Networks']['office-lan']['IPAddress']
    if not address and record.get('State', {}).get('Running') is False:
        return  # Read-only historical logs; no address is contacted.
    if ipaddress.ip_address(address) not in ipaddress.ip_network('172.20.0.0/16'):
        raise ValueError('Container outside owned subnet')


def collect(since):
    folder = ROOT / 'private/monitoring/container-logs'
    folder.mkdir(exist_ok=True, parents=True)
    secret_values = []
    for path in (ROOT / '.env', Path(LAB) / '.env'):
        if path.exists():
            for line in path.read_text().splitlines():
                if '=' in line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    value = value.strip().strip('\'"').replace('$$', '$')
                    if re.search('PASSWORD|TOKEN|SECRET|KEY|HASH', key) and len(value) >= 8:
                        secret_values.append(value)
    register = []
    for service in SERVICES:
        ids = docker('ps', '-a', '-q', '--filter', 'label=com.docker.compose.project=it-support-homelab',
                     '--filter', f'label=com.docker.compose.service={service}').stdout.split()
        if len(ids) != 1:
            raise ValueError(f'Expected one uniquely identified owned service: {service}')
        record = json.loads(docker('inspect', ids[0]).stdout)[0]
        validate_container(record, service)
        logs = docker('logs', '--timestamps', '--since', since, '--tail', '2000', ids[0])
        lines = (logs.stdout + logs.stderr).splitlines()
        with (folder / f'{service}.log').open('a', encoding='utf-8') as out:
            for line in lines:
                for value in secret_values:
                    line = line.replace(value, '[REDACTED]')
                # WireGuard configuration and keys must never enter the SIEM.
                if re.search(r'(?i)(privatekey|presharedkey|authorization:|password=|token=)', line):
                    continue
                out.write(f'{datetime.now(timezone.utc):%b %d %H:%M:%S} homelab {service}: {line}\n')
        register.append({'service': service, 'container_id': record['Id'], 'lines': len(lines),
                         'source': 'Docker stdout/stderr', 'since': since, 'running': record['State']['Running']})
    (ROOT / 'private/monitoring/container-collection.json').write_text(json.dumps(register, indent=2))
    print(json.dumps(register, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--since', default='15m')
    collect(parser.parse_args().since)
