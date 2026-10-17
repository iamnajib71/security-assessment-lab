"""Fail before publication if candidate Git files contain local lab secrets."""
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parents[1]
p = subprocess.run(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=root, capture_output=True, check=True)
files = set(p.stdout.decode().split('\0')) - {''}
secrets = []
labenv = root.parent / 'it-support-homelab/.env'
if labenv.exists():
    for line in labenv.read_text().splitlines():
        if '=' not in line or line.startswith('#'): continue
        key, value = line.split('=', 1)
        value = value.strip().strip('"\'').replace('$$', '$')
        if re.search('PASSWORD|TOKEN|KEY|HASH', key) and len(value) >= 8:
            secrets.append(value.encode())
bad = []
for name in sorted(files):
    path = root / name
    if path.name in {'AGENTS.md', 'CLAUDE.md', '.env'} or name.startswith('private/'):
        bad.append(name + ': forbidden file'); continue
    data = path.read_bytes()
    if any(secret in data for secret in secrets):
        bad.append(name + ': local credential value')
    # Source code may describe the markers; only complete private-key blocks fail.
    if re.search(rb'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{20,}?-----END', data):
        bad.append(name + ': private key block')
    if re.search(rb'gh[pousr]_[A-Za-z0-9]{30,}', data):
        bad.append(name + ': GitHub token')
if bad:
    raise SystemExit('\n'.join(bad))
print(f'{len(files)} candidate Git files checked; no forbidden files or detected credentials')
