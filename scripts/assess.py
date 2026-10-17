"""Local assessment entry point. All subprocesses use argument arrays, never shells."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

from core import HOST_PORTS, parse_nmap, parse_nuclei, validate_scope, validate_target
from smb_negotiate import signing_policy

ROOT = Path(__file__).resolve().parents[1]


def command(args, *, data=None, check=True, timeout=900):
    p = subprocess.run(args, input=data.encode('utf-8') if data is not None else None, capture_output=True, timeout=timeout)
    p.stdout = p.stdout.decode('utf-8', errors='replace')
    p.stderr = p.stderr.decode('utf-8', errors='replace')
    if check and p.returncode:
        raise RuntimeError(f'{args[0]} failed ({p.returncode}): {p.stderr}')
    return p


def get_scope(lab):
    base = ['docker', 'compose', '--project-directory', str(lab)]
    ids = command(base + ['ps', '-q']).stdout.split()
    if not ids:
        raise RuntimeError('Homelab is stopped. Start it before assessment.')
    records = json.loads(command(['docker', 'inspect', *ids]).stdout)
    network = json.loads(command(['docker', 'network', 'inspect', 'office-lan']).stdout)[0]
    if {c['Subnet'] for c in network['IPAM']['Config']} != {'172.20.0.0/16'}:
        raise ValueError('office-lan subnet does not match authorization')
    return base, validate_scope(records, network['Containers']), records


def request(url, ca=None):
    from urllib.parse import urlsplit
    u = urlsplit(url)
    if u.hostname != '127.0.0.1' or u.port not in (51821, 13001, 6631):
        raise ValueError('HTTP target outside fixed loopback allow-list')
    handlers = [urllib.request.ProxyHandler({})]
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args):
            return None
    handlers.append(NoRedirect())
    if ca:
        handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))))
    try:
        with urllib.request.build_opener(*handlers).open(url, timeout=10) as r:
            body = r.read(200000)
            return {'url': url, 'status': r.status, 'server': r.headers.get('Server'),
                    'basic_challenge': r.headers.get('WWW-Authenticate'),
                    'body_sha256': hashlib.sha256(body).hexdigest()}
    except urllib.error.HTTPError as e:
        return {'url': url, 'status': e.code, 'basic_challenge': e.headers.get('WWW-Authenticate')}
    except (OSError, urllib.error.URLError) as e:
        return {'url': url, 'status': None, 'error': str(e)}


SMB_CHECK = r'''set -eu
f=$(mktemp); chmod 600 "$f"; trap 'rm -f "$f"' EXIT
printf 'username = alice\npassword = %s\n' "$SMB_ALICE_PASSWORD" > "$f"
echo '$ smbclient //127.0.0.1/Finance -A [private credential file] -c ls --option="client signing=disabled"'
set +e
smbclient //127.0.0.1/Finance -A "$f" -c ls --option='client signing=disabled' 2>&1
rc=$?
set -e
echo "UNSIGNED_RC=$rc"
echo '$ smbclient -L //127.0.0.1 -N'
smbclient -L //127.0.0.1 -N 2>&1 || true
for share in Public Finance Scans; do
 echo "GUEST $share"
 set +e
 smbclient "//127.0.0.1/$share" -N -c ls 2>&1
 echo "GUEST_${share}_RC=$?"
 set -e
done
echo 'SIGNED Alice Finance (must succeed)'
smbclient //127.0.0.1/Finance -A "$f" -c ls --option='client signing=required' 2>&1
echo 'SIGNED_ALICE_RC=0'
printf 'username = bob\npassword = %s\n' "$SMB_BOB_PASSWORD" > "$f"
echo 'BOB Finance (must deny)'
set +e
smbclient //127.0.0.1/Finance -A "$f" -c ls 2>&1
echo "BOB_FINANCE_RC=$?"
set -e
echo 'BOB Public (authorized shared access)'
smbclient //127.0.0.1/Public -A "$f" -c ls 2>&1
echo 'EFFECTIVE CONFIGURATION'
testparm -s 2>&1
'''

AD_CHECK = r'''import json, secrets, subprocess
def call(args):
 p=subprocess.run(args,capture_output=True,text=True)
 return p.returncode,p.stdout+p.stderr
name='assessment_probe'
rc,out=call(['samba-tool','user','show',name])
if rc==0: raise SystemExit('Refusing to overwrite an existing assessment_probe account')
p1='Aa1!'+secrets.token_hex(18); p2='Bb2!'+secrets.token_hex(18); p3='Cc3!'+secrets.token_hex(18)
try:
 rc,out=call(['samba-tool','user','create',name,p1,'--userou=OU=Staff'])
 if rc: raise RuntimeError(out)
 print('Temporary fictional assessment_probe created with random strong password')
 results=[]
 for old,new in [(p1,p2),(p2,p3)]:
  rc,out=call(['samba-tool','user','password','-U'+name+'%'+old,'--ipaddress=127.0.0.1','--newpassword='+new])
  for secret in [p1,p2,p3]: out=out.replace(secret,'[private random password]')
  print('SELF_CHANGE_RC='+str(rc)); print(out.strip()); results.append(rc)
  if rc: break
 print('RAPID_CHANGES_ALLOWED='+str(results==[0,0]).lower())
finally:
 rc,out=call(['samba-tool','user','delete',name]); print(out.strip())
 if rc: raise RuntimeError('Temporary account cleanup failed')
'''


def collect(lab, phase, target=None, skip_scan=False):
    base, scope, records = get_scope(lab)
    if target is not None:
        validate_target(target, scope)
        # Validation-only target argument; full assessment always uses five lab hosts.
    run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + phase
    out = ROOT / 'evidence' / run_id
    out.mkdir(parents=True, exist_ok=False)
    def save(name, value):
        (out / name).write_text(value, encoding='utf-8')
    save('scope.json', json.dumps(scope, indent=2))
    # Never persist docker inspect/config, which contain real generated lab secrets.
    images = [{'service': r['Config']['Labels']['com.docker.compose.service'], 'image': r['Config']['Image'],
               'image_id': r['Image']} for r in records]
    save('images.json', json.dumps(images, indent=2))
    if skip_scan:
        raise ValueError('Live assessments require actual scans')
    print('Running bounded discovery, TCP services and Nuclei (five exact office-lan IPs)...', flush=True)
    p = command(['docker', 'run', '--rm', '--network', 'office-lan', '--cap-drop', 'ALL',
                 '--cap-add', 'NET_ADMIN', '--cap-add', 'NET_RAW', '--security-opt', 'no-new-privileges',
                 '-e', 'LAB_SCOPE=' + json.dumps(scope), '-e', 'DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD=true',
                 '-v', f'{out}:/evidence', 'security-assessment-scanner:1'])
    save('scanner.txt', p.stdout + p.stderr)
    inventory = parse_nmap((out / 'services.xml').read_text(), scope)
    if (out / 'wg-admin.xml').exists():
        extra = parse_nmap((out / 'wg-admin.xml').read_text(), scope)
        for host in inventory:
            if host['asset'] == 'wireguard':
                host['ports'].extend(p for x in extra for p in x['ports'] if p['port'] not in [y['port'] for y in host['ports']])
    save('inventory.json', json.dumps(inventory, indent=2))
    rows = ['# Live asset inventory', '', '| Asset | IP | TCP port | Service | Version |', '|---|---|---|---|---|']
    for host in inventory:
        for port in host['ports']:
            rows.append(f"| {host['asset']} | {host['address']} | {port['port']} | {port['service']} | {port['version']} |")
    save('inventory.md', '\n'.join(rows) + '\n')
    nuclei_path = out / 'nuclei.jsonl'
    if not nuclei_path.exists():
        nuclei_path.write_text('')
    nuclei = parse_nuclei(nuclei_path.read_text(), scope)
    save('nuclei-normalized.json', json.dumps(nuclei, indent=2))
    print('Collecting SMB permissions, AD policy/ACLs and loopback transport checks...', flush=True)
    smb = command(base + ['exec', '-T', 'fileserver', 'sh', '-s'], data=SMB_CHECK).stdout
    save('smb-manual.txt', smb)
    signing = signing_policy()
    save('smb-negotiate.json', json.dumps(signing, indent=2))
    policy = command(base + ['exec', '-T', 'directory', 'samba-tool', 'domain', 'passwordsettings', 'show']).stdout
    save('ad-policy.txt', policy)
    ad = command(base + ['exec', '-T', 'directory', 'python3', '-'], data=AD_CHECK).stdout
    save('ad-manual.txt', ad)
    ad_review = []
    for group in ['Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Account Operators', 'GG-IT-Admins']:
        p = command(base + ['exec', '-T', 'directory', 'samba-tool', 'group', 'listmembers', group])
        ad_review.append('$ samba-tool group listmembers ' + group + '\n' + p.stdout)
    for dn in ['DC=itops,DC=lab', 'OU=Staff,DC=itops,DC=lab', 'OU=Finance,DC=itops,DC=lab']:
        p = command(base + ['exec', '-T', 'directory', 'samba-tool', 'dsacl', 'get', '--objectdn=' + dn])
        ad_review.append('$ samba-tool dsacl get --objectdn=' + dn + '\n' + p.stdout)
    save('ad-groups-acls.txt', '\n'.join(ad_review))
    # Local secret quality review only; no guessing, no lockouts and no password output.
    env = {}
    for line in (lab / '.env').read_text().splitlines():
        if '=' in line and not line.startswith('#'):
            k, v = line.split('=', 1); env[k] = v.strip().strip('"\'')
    weak = []
    defaults = {'password', 'password123!', 'admin', 'changeme', 'welcome1!', 'print'}
    for key in ['AD_ALICE_PASSWORD', 'AD_BOB_PASSWORD', 'AD_CAROL_PASSWORD', 'WG_ADMIN_PASSWORD', 'KUMA_ADMIN_PASSWORD', 'CUPS_ADMIN_PASSWORD']:
        value = env.get(key, '')
        weak.append({'account_key': key, 'present': bool(value), 'weak_or_common_default': len(value) < 12 or value.lower() in defaults})
    save('credential-quality.json', json.dumps(weak, indent=2))
    http = [request(f'http://127.0.0.1:{port}' + ('/admin/' if port == 6631 else '/')) for port in (51821, 13001, 6631)]
    ca = lab / 'homelab' / 'tls' / 'lab-root.crt'
    https = [request(f'https://127.0.0.1:{port}' + ('/admin/' if port == 6631 else '/'), ca) for port in (51821, 13001, 6631)] if ca.exists() else []
    save('http-manual.json', json.dumps({'http': http, 'https': https}, indent=2))
    # Login pages are public by design; probe a protected API separately.
    wg_auth = request(('https' if ca.exists() else 'http') + '://127.0.0.1:51821/api/wireguard/client', ca if ca.exists() else None)
    kuma_js = r'''const {io}=require('/app/node_modules/socket.io-client');
const s=io('http://127.0.0.1:3001',{transports:['websocket'],reconnection:false});
s.on('connect',()=>{s.emit('needSetup',v=>console.log('needSetup='+v));s.emit('getMonitorList',r=>{console.log(JSON.stringify(r));s.close();process.exit(0);});});
setTimeout(()=>{console.log('No unauthenticated monitor response within 5s; no bypass claimed');s.close();process.exit(0)},5000);'''
    kuma_auth = command(base + ['exec', '-T', 'uptime', 'node', '-e', kuma_js]).stdout
    save('admin-auth.json', json.dumps({'wireguard_anonymous_protected_api': wg_auth, 'kuma_anonymous': kuma_auth}, indent=2))
    versions = {}
    for service, args in [('wireguard', ['node', '-p', 'require("/app/package.json").version']),
                          ('uptime', ['node', '-p', 'require("/app/package.json").version']),
                          ('fileserver', ['smbd', '--version']), ('directory', ['samba', '--version']),
                          ('printserver', ['dpkg-query', '-W', '-f=${Version}\n', 'cups-daemon'])]:
        p = command(base + ['exec', '-T', service, *args], check=False)
        versions[service] = {'returncode': p.returncode, 'output': (p.stdout+p.stderr).strip()}
    save('runtime-versions.json', json.dumps(versions, indent=2))
    loopback = []
    for port in HOST_PORTS:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=3):
                opened = True
        except OSError:
            opened = False
        loopback.append({'address': '127.0.0.1', 'port': port, 'open': opened})
    save('loopback-inventory.json', json.dumps(loopback, indent=2))
    checks = {'run_id': run_id, 'phase': phase, 'timestamp': datetime.now(timezone.utc).isoformat(),
              'scope': scope, 'controls': {
                  'smb_signing_required': signing['signing_required'] and 'server signing = required' in smb and 'SIGNED_ALICE_RC=0' in smb,
                  'ad_min_age': 'Minimum password age (days): 0' not in policy and 'RAPID_CHANGES_ALLOWED=false' in ad,
                  'admin_tls': len(https) == 3 and all(x['status'] in (200, 302, 401) for x in https) and all(x['status'] not in (200, 302, 401) for x in http)},
              'observations': {'guest_readable_shares': [s for s in ('Public', 'Finance', 'Scans') if f'GUEST_{s}_RC=0' in smb],
                               'bob_finance_allowed': 'BOB_FINANCE_RC=0' in smb,
                               'weak_or_default_credentials': [w['account_key'] for w in weak if w['weak_or_common_default']],
                               'wg_anonymous_protected_api_status': wg_auth['status']},
              'nuclei_matches': len(nuclei), 'inventory_hosts': len(inventory)}
    save('checks.json', json.dumps(checks, indent=2))
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.iterdir()) if p.is_file()}
    save('sha256.json', json.dumps(hashes, indent=2))
    print(json.dumps(checks['controls'], indent=2), flush=True)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--lab', type=Path, default=ROOT.parent / 'it-support-homelab')
    ap.add_argument('--phase', choices=['baseline', 'retest', 'current'], default='current')
    ap.add_argument('--target', help='Optional target validation; accepts only current allow-listed lab identities')
    args = ap.parse_args()
    lab = args.lab.resolve()
    if not (lab / 'docker-compose.yml').exists() or lab.name != 'it-support-homelab':
        ap.error('Only the sibling it-support-homelab project is authorized')
    out = collect(lab, args.phase, args.target)
    command([sys.executable, str(ROOT / 'scripts' / 'report.py'), '--current', str(out)])
    print(f'Report: {ROOT / "report/security-assessment.md"}')
    if args.phase == 'retest' and not all(json.loads((out / 'checks.json').read_text())['controls'].values()):
        raise SystemExit('Retest incomplete: at least one control failed')


if __name__ == '__main__':
    main()
