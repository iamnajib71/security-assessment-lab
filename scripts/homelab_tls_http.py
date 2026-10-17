"""Standard-library TLS adapter for the homelab's PowerShell 5.1 checks.

Installed as tests/tls_http.py by remediate.py. Requests arrive via stdin so
credentials are never command-line arguments or evidence output.
"""
import http.cookiejar
import json
from pathlib import Path
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
from urllib.parse import urlsplit

r = json.load(sys.stdin)
u = urlsplit(r['url'])
if u.hostname != '127.0.0.1' or (u.scheme, u.port) not in {('https', 51821), ('https', 13001), ('https', 6631), ('http', 13002)}:
    raise SystemExit('Refused non-lab HTTP request')
ca = Path(__file__).resolve().parents[1] / 'homelab/tls/lab-root.crt'
handlers = [urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca)))]
jar = None
if r.get('cookie_jar'):
    path = Path(r['cookie_jar']).resolve()
    if path.parent != Path(tempfile.gettempdir()).resolve() or not path.name.startswith('homelab-wg-'):
        raise SystemExit('Refused cookie jar outside temporary lab session')
    jar = http.cookiejar.LWPCookieJar(str(path))
    if path.exists() and path.stat().st_size: jar.load(ignore_discard=True)
    handlers.append(urllib.request.HTTPCookieProcessor(jar))
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).netloc != urlsplit(req.full_url).netloc:
            raise ValueError('Refused redirect outside same loopback origin')
        return super().redirect_request(req, fp, code, msg, headers, newurl)
handlers.append(NoRedirect())
body = r.get('body')
headers = r.get('headers') or {}
if r.get('content_type'): headers['Content-Type'] = r['content_type']
req = urllib.request.Request(r['url'], data=body.encode() if body else None, headers=headers, method=(r.get('method') or 'GET').upper())
try:
    response = urllib.request.build_opener(*handlers).open(req, timeout=30)
except urllib.error.HTTPError as e:
    response = e
with response:
    data = {'StatusCode': response.code, 'Content': response.read().decode('utf-8', 'replace')}
if jar: jar.save(ignore_discard=True)
print(json.dumps(data))
