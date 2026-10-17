"""Scanner container: no Docker socket, no credentials, no arbitrary options.

    Enforce an egress allow-list in this network namespace before any probes.
"""
import ipaddress
import json
import os
from pathlib import Path
import subprocess

scope = json.loads(os.environ['LAB_SCOPE'])
if set(scope) != {'wireguard', 'fileserver', 'printserver', 'uptime', 'directory'}:
    raise SystemExit('Invalid scope')
for ip in scope.values():
    if ipaddress.ip_address(ip) not in ipaddress.ip_network('172.20.0.0/16'):
        raise SystemExit('Out-of-scope address')


def run(args, filename=None):
    result = subprocess.run(args, capture_output=True, text=True, timeout=600)
    if filename:
        Path('/evidence', filename).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed ({result.returncode}): {result.stderr}')
    return result.stdout


run(['iptables', '-P', 'OUTPUT', 'DROP'])
for ip in scope.values():
    run(['iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'ACCEPT'])
run(['ip6tables', '-P', 'OUTPUT', 'DROP'])
run(['iptables', '-S', 'OUTPUT'], 'firewall.txt')
run(['nmap', '--version'], 'nmap-version.txt')
run(['nuclei', '-version'], 'nuclei-version.txt')
targets = list(scope.values())
run(['nmap', '-n', '-sn', '-oA', '/evidence/discovery', *targets], 'discovery-console.txt')
run(['nmap', '-n', '-sT', '-Pn', '-sV', '--version-light', '--top-ports', '1000',
     '--script', '(default and safe) and not (external or broadcast or intrusive or dos or exploit or brute or fuzzer)',
     '--script-timeout', '15s', '--host-timeout', '240s', '--max-rate', '75',
     '-oA', '/evidence/services', *targets], 'services-console.txt')
run(['nmap', '-n', '-sT', '-Pn', '-sV', '--version-light', '-p', '51821',
     '--script', 'http-title,http-headers', '--script-timeout', '10s', '--max-rate', '10',
     '-oA', '/evidence/wg-admin', scope['wireguard']], 'wg-admin-console.txt')
urls = [f"http://{scope[s]}:{p}" for s, p in [('wireguard', 51821), ('uptime', 3001), ('printserver', 631)]]
Path('/evidence/urls.txt').write_text('\n'.join(urls) + '\n')
# Only vendored community GET templates; no redirects, no OAST, no updates,
# no cloud upload, no code/headless/fuzzing/default-login templates.
run(['nuclei', '-l', '/evidence/urls.txt', '-t', '/templates', '-jsonl',
     '-o', '/evidence/nuclei.jsonl', '-duc', '-ni', '-dr', '-rl', '2', '-c', '1',
     '-bs', '1', '-timeout', '5', '-retries', '0', '-nc', '-silent', '-dut', '-or', '-ot'], 'nuclei-console.txt')
print('Discovery, TCP services and reviewed Nuclei templates completed.')
