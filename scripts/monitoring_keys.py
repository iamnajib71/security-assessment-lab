"""Register only DC01/CLIENT01 and save their agent keys privately, never print keys."""
from pathlib import Path
import json
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def manage(*args):
    return subprocess.run(['docker', 'exec', '-i', 'soc-lab-wazuh.manager-1',
                           '/var/ossec/bin/manage_agents', *args], input='y\n',
                          capture_output=True, text=True, check=True).stdout


def register():
    private = ROOT / 'private/monitoring'
    for name in ('DC01', 'CLIENT01'):
        if (private / f'{name}.key').exists():
            raise ValueError(f'{name} already registered; refusing key rotation')
    for name in ('DC01', 'CLIENT01'):
        output = manage('-a', 'any', '-n', name)
        found = re.search(r'ID\s*:?\s*(\d+)', output)
        if not found:
            raise ValueError('Registration did not return an agent ID; inspect manager privately')
        ident = found.group(1)
        key_output = manage('-e', ident)
        candidates = re.findall(r'^[A-Za-z0-9+/=]{60,}$', key_output, re.M)
        if len(candidates) != 1:
            raise ValueError('Key export format unexpected')
        (private / f'{name}.key').write_text(candidates[0].strip() + '\n')
        (private / f'{name}-id.json').write_text(json.dumps({'name': name, 'id': ident}))
        print(f'{name}: agent {ident} registered; key saved privately')


if __name__ == '__main__':
    register()
