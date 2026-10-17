"""Apply three bounded, persistent hardening changes to the owned sibling homelab.

This never weakens controls or seeds vulnerabilities. Back up configuration to the
ignored private/ directory. Existing named data volumes and credentials are retained.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import time

from assess import ROOT, command, get_scope, request

CADDY = '''{
    admin off
    auto_https disable_redirects
    default_sni 127.0.0.1
}
https://127.0.0.1:51821 {
    tls internal
    reverse_proxy wireguard:51821
}
https://127.0.0.1:13001 {
    tls internal
    reverse_proxy uptime:3001
}
https://127.0.0.1:6631 {
    tls internal
    reverse_proxy printserver:631
}
'''


def remediate(lab):
    base, scope, _ = get_scope(lab)
    lab = lab.resolve()
    if lab.name != 'it-support-homelab':
        raise ValueError('Only the owned it-support-homelab is authorized')
    backup = ROOT / 'private' / 'pre-hardening'
    backup.mkdir(parents=True, exist_ok=True)
    compose = lab / 'docker-compose.yml'
    seed = lab / 'homelab/ad/seed.sh'
    for path in [compose, seed, lab / 'tests/homelab_check.ps1', lab / 'tests/lab_helpers.ps1']:
        dest = backup / path.name
        if not dest.exists():
            shutil.copyfile(path, dest)
    text = compose.read_text()
    if 'server signing = mandatory' not in text:
        needle = '      -p\n'
        if text.count(needle) != 1:
            raise ValueError('Unexpected fileserver command; review before changing')
        text = text.replace(needle, '      -g "server signing = mandatory"\n' + needle)
    if '\n  admin-tls:\n' not in text:
        for old, new in [
            ('ports: ["127.0.0.1:51820:51820/udp", "127.0.0.1:51821:51821/tcp"]', 'ports: ["127.0.0.1:51820:51820/udp"]'),
            ('    ports: ["127.0.0.1:6631:631"]\n', ''),
            ('    ports: ["127.0.0.1:13001:3001"]\n', '')]:
            if text.count(old) != 1:
                raise ValueError('Unexpected admin port configuration')
            text = text.replace(old, new)
        proxy = '''  admin-tls:
    image: caddy:2.11.7-alpine@sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f
    restart: unless-stopped
    ports: ["127.0.0.1:51821:51821", "127.0.0.1:13001:13001", "127.0.0.1:6631:6631"]
    volumes:
      - ./homelab/tls/Caddyfile:/etc/caddy/Caddyfile:ro
      - admin_tls_data:/data
      - admin_tls_config:/config
    depends_on: [wireguard, uptime, printserver]

'''
        text = text.replace('\nvolumes:\n', '\n' + proxy + 'volumes:\n  admin_tls_data:\n  admin_tls_config:\n')
    tls = lab / 'homelab/tls'
    tls.mkdir(parents=True, exist_ok=True)
    (tls / 'Caddyfile').write_text(CADDY, newline='\n')
    compose.write_text(text, newline='\n')
    policy = seed.read_text()
    if '--min-pwd-age=0' not in policy and '--min-pwd-age=1' not in policy:
        raise ValueError('Unexpected AD policy configuration')
    seed.write_text(policy.replace('--min-pwd-age=0', '--min-pwd-age=1'), newline='\n')
    # Keep the existing end-to-end support checks working with actual TLS trust
    # under Windows PowerShell 5.1, without installing a global CA or bypassing it.
    shutil.copyfile(ROOT / 'scripts/homelab_tls_http.py', lab / 'tests/tls_http.py')
    helper = lab / 'tests/lab_helpers.ps1'
    h = helper.read_text(encoding='utf-8-sig')
    if '# TLS adapter: explicit lab CA' not in h:
        h = h.replace('$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession',
                      "$session = [PSCustomObject]@{CookieJar=(Join-Path ([IO.Path]::GetTempPath()) ('homelab-wg-' + [Guid]::NewGuid().ToString('N') + '.txt'))}")
        h += (ROOT / 'scripts/homelab_tls_helpers.ps1').read_text()
    for port in (51821, 13001, 6631): h = h.replace('http://127.0.0.1:' + str(port), 'https://127.0.0.1:' + str(port))
    h = h.replace('Invoke-RestMethod', 'Invoke-LabRestMethod')
    helper.write_text(h, encoding='utf-8-sig', newline='\n')
    checks = lab / 'tests/homelab_check.ps1'
    c = checks.read_text(encoding='utf-8-sig')
    for port in (51821, 13001, 6631): c = c.replace('http://127.0.0.1:' + str(port), 'https://127.0.0.1:' + str(port))
    c = c.replace('Invoke-WebRequest', 'Invoke-LabWebRequest').replace('Invoke-RestMethod', 'Invoke-LabRestMethod')
    old = "try { $null = Invoke-LabWebRequest -UseBasicParsing -Uri 'https://127.0.0.1:6631/admin/' -TimeoutSec 15 }\n        catch { if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode } else { throw } }"
    c = c.replace(old, "$status = (Invoke-LabWebRequest -Uri 'https://127.0.0.1:6631/admin/' -AllowError).StatusCode")
    if 'Remove-Item -LiteralPath $session.CookieJar' not in c:
        c = c.replace("Write-Evidence 'DELETE peer => success; absent on subsequent GET'", "Write-Evidence 'DELETE peer => success; absent on subsequent GET'\n        Remove-Item -LiteralPath $session.CookieJar -Force -ErrorAction SilentlyContinue")
    checks.write_text(c, encoding='utf-8-sig', newline='\n')
    for relative in ['README.md', 'docs/homelab-runbook.md', 'homelab/dashboard/services.yaml']:
        path = lab / relative
        content = path.read_text(encoding='utf-8-sig')
        for port in (51821, 13001, 6631):
            content = content.replace('http://127.0.0.1:' + str(port), 'https://127.0.0.1:' + str(port))
        if relative.endswith('.md') and 'Security assessment hardening' not in content:
            content += '\n\n## Security assessment hardening\n\nOwner-authorized assessment on 17 October 2026: mandatory SMB signing, AD minimum password age one day, and local TLS on admin ports 51821, 13001 and 6631. Use the explicit public CA at `homelab/tls/lab-root.crt` (`curl --cacert`); the private key stays in the Caddy data volume. Internal office-lan monitoring still uses HTTP. The companion security-assessment-lab repository contains before/after evidence and the report.\n'
        path.write_text(content, encoding='utf-8', newline='\n')
    command(base + ['exec', '-T', 'directory', 'samba-tool', 'domain', 'passwordsettings', 'set', '--min-pwd-age=1'])
    print('Persistent SMB signing, AD minimum age and TLS proxy configuration written.', flush=True)
    command(base + ['up', '-d', 'fileserver', 'wireguard', 'uptime', 'printserver', 'admin-tls'])
    command(base + ['restart', 'admin-tls'])
    # The upstream Samba image retains a name cache in an anonymous volume;
    # container recreation can reassign IPs. Flush only this resolution cache.
    command(base + ['exec', '-T', 'fileserver', 'net', 'cache', 'flush'])
    # Only the CA PUBLIC certificate leaves the Caddy volume. Never export a key.
    ca = tls / 'lab-root.crt'
    for _ in range(30):
        p = command(base + ['exec', '-T', 'admin-tls', 'cat', '/data/caddy/pki/authorities/local/root.crt'], check=False)
        if p.returncode == 0 and 'BEGIN CERTIFICATE' in p.stdout:
            ca.write_text(p.stdout, newline='\n')
            break
        time.sleep(1)
    else:
        raise RuntimeError('TLS CA public certificate not ready')
    for _ in range(40):
        checks = [request('https://127.0.0.1:' + str(p) + '/', ca) for p in (51821, 13001, 6631)]
        if all(c['status'] in (200, 302) for c in checks):
            break
        time.sleep(1)
    else:
        raise RuntimeError('TLS service readiness failed: ' + json.dumps(checks))
    print('All three admin HTTPS endpoints validate with the explicit lab CA.', flush=True)


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--lab', type=Path, default=ROOT.parent / 'it-support-homelab')
    args = ap.parse_args()
    remediate(args.lab)
