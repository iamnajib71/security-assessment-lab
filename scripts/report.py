"""Generate Markdown, PDF and a static sample report from evidence, never fixtures."""
import argparse
from collections import Counter
from datetime import datetime
from html import escape
import json
import re
from pathlib import Path

from core import findings

ROOT = Path(__file__).resolve().parents[1]
LIMITS = ('Owner-performed assessment of five local Docker services and fixed loopback ports. '
          'Top 1,000 TCP ports plus the known wg-easy admin port; no UDP sweep, external targets, denial of service, destructive exploits, '
          'password cracking, full CVE coverage, AD attack paths, Windows domain join, GPO or production monitoring. '
          'Known tools and four reviewed Nuclei templates. No assertion of paid penetration-testing, '
          'OSCP-level exploitation or production SOC/incident-response experience. '
          'Privileged Docker operators can access credentials and bypass controls. '
          'The proxy encrypts host-facing admin access; HTTP on the isolated office-lan remains a residual risk. '
          'Default-password checks review only the fictional credentials in the local ignored .env; no dictionary guessing. '
          'Observed image tags/versions do not prove current patch status. No unsupported CVE claims are made.')


def load_run(path):
    path = Path(path)
    data = json.loads((path / 'checks.json').read_text())
    for name, digest in json.loads((path / 'sha256.json').read_text()).items():
        import hashlib
        if hashlib.sha256((path / name).read_bytes()).hexdigest() != digest:
            raise ValueError('Evidence hash mismatch: ' + name)
    return data


def generate(current_path, output=None):
    current_path = Path(current_path)
    output = Path(output or ROOT / 'report')
    output.mkdir(parents=True, exist_ok=True)
    current = load_run(current_path)
    baselines = sorted(p for p in (ROOT / 'evidence').glob('*-baseline') if (p / 'checks.json').exists())
    baseline_path = baselines[0] if baselines else current_path
    baseline = load_run(baseline_path)
    rows = findings(baseline, current)
    inventory = json.loads((current_path / 'inventory.json').read_text())
    matches = json.loads((current_path / 'nuclei-normalized.json').read_text())
    runtime_path = current_path / 'runtime-versions.json'
    runtime = json.loads(runtime_path.read_text()) if runtime_path.exists() else {}
    version_review = 'Runtime checks (failed commands remain explicitly unknown):\n\n'
    version_review += '\n'.join(f"- {name}: {item['output'] if item['returncode'] == 0 else 'unknown; see raw command failure'}" for name, item in runtime.items()) or 'Not collected in this run.'
    version_review += ('\n\nThe baseline Nmap guessed Samba 4.6.2; the runtime file-server check reported 4.12.2. '
                       'Prefer runtime/package evidence over fingerprints. The wg-easy image track is 14; its internal package.json version is not a release-track version. '
                       'Official references checked on 17 October 2026 were wg-easy v15.4.0, Uptime Kuma 2.5.6 and CUPS v2.4.20. '
                       'The baseline ran older release tracks; schedule compatibility, migration and security-advisory review. '
                       'Reference metadata is dated, not refreshed by local scanning. No version-only CVE finding or assumption about distribution backports is made. '
                       'No major-version upgrade was performed in the three remediation loops. '
                       '[Official release metadata](../evidence/version-reference.json); runtime-versions.json is linked in the raw index.')
    counts = Counter(r['severity'] for r in rows)
    closed = sum(r['status'] == 'Fixed - retested' for r in rows)
    summary = (f"{len(rows)} confirmed findings: {counts['Medium']} Medium, {counts['Low']} Low, "
               f"{counts['High']} High, {counts['Critical']} Critical. {closed} fixed and retested; "
               f"{len(rows)-closed} open or unverified. {len(inventory)} service hosts inventoried. "
               f"The latest unauthenticated Nuclei pass produced {len(matches)} informational template matches; "
               'these are observations, not automatically confirmed vulnerabilities.')
    if not rows:
        summary += ' No baseline-confirmed finding is available; this is not a clean bill of health.'
    sections = [('# Security assessment - IT Support Homelab',
                 '**Authorization: all targets are my own homelab; testing performed by the owner, Nazmul Hassan.**\n\n'
                 'Owner-authorized local learning and assessment. No third-party engagement.\n\n'
                 f"Baseline: `{baseline['run_id']}`. Latest assessment: `{current['run_id']}` (UTC timestamps)."),
                ('## Executive summary', summary),
                ('## Scope and rules of engagement',
                 'Only current Compose containers labelled project `it-support-homelab` and services '
                 '`fileserver`, `directory`, `printserver`, `wireguard`, `uptime` on `office-lan` '
                 '`172.20.0.0/16`, plus 127.0.0.1 ports 1445, 1389, 1636, 51821, 13001, 6631. '
                 'Discovery uses their exact inspected addresses, never a /16 sweep. Homepage is supporting infrastructure, not scanned. '
                 'The local TLS proxy is a remediation control and is checked through the same loopback ports. '
                 'No internet/third-party targets, live cracking, destructive exploits or denial of service. '
                 'Only fictional users alice, bob, carol and a temporary assessment_probe are used. '
                 'The scanner has no Docker socket or credentials; IPv4 egress is limited to the five lab addresses, IPv6 is blocked. '
                 'Redirects, external NSE categories, OAST and scanner updates are disabled. Tool installation may download public packages.'),
                ('## Methodology and severity',
                 '1. Validate Compose labels, network membership, addresses and loopback bindings.\n'
                 '2. Nmap host discovery and top-1000 TCP connect/version discovery, using default AND safe NSE scripts with dangerous/external categories excluded.\n'
                 '3. Nuclei v3.11.1 with four pinned community HTTP GET templates, two requests/second, no redirects or OAST.\n'
                 '4. Authenticated Samba access/ACL and AD policy/group/ACL checks; credential-quality review; admin transport/auth checks.\n'
                 '5. Manually supervised minimal proofs, persistent remediation, and repeat checks.\n'
                 '6. Preserve raw output and SHA-256 manifests; normalize to JSON/Markdown and generate this PDF.\n\n'
                 'Ratings are CVSS-style qualitative priorities, adjusted for actual access prerequisites and impact. '
                 'No numeric score is invented. Critical/High require demonstrated substantial impact; Medium has a credible '
                 'adjacent-network integrity/confidentiality risk; Low covers constrained policy/transport weaknesses; '
                 'Informational observations are not counted as vulnerabilities. Scanner suggestions require analyst review.'),
                ('## Findings register', '')]
    table = ['| ID | Asset | Severity | Finding | Evidence | Remediation | Status |', '|---|---|---|---|---|---|---|']
    for r in rows:
        table.append(f"| {r['id']} | {r['asset']} | {r['severity']} | {r['title']} | [before]({r['evidence'][0]}) / [after]({r['evidence'][1]}) | {r['remediation']} | {r['status']} |")
    sections[-1] = (sections[-1][0], '\n'.join(table))
    for r in rows:
        stem = {'SAL-01': 'smb-manual.txt', 'SAL-02': 'ad-manual.txt', 'SAL-03': 'http-manual.json'}[r['id']]
        proof = f"[Baseline raw proof](../evidence/{baseline['run_id']}/{stem}) and [retest raw proof](../evidence/{current['run_id']}/{stem})."
        if r['id'] == 'SAL-01':
            before_inventory = json.loads((baseline_path/'inventory.json').read_text())
            b = next((h['scripts'].get('smb2-security-mode', 'not collected') for h in before_inventory if h['asset']=='fileserver'), 'not collected')
            a = next((h['scripts'].get('smb2-security-mode', 'not collected') for h in inventory if h['asset']=='fileserver'), 'not collected')
            negotiate = current_path/'smb-negotiate.json'
            n = json.loads(negotiate.read_text()) if negotiate.exists() else {}
            detail = f"**Observed protocol evidence:** baseline: {b.strip()}; latest: {a.strip()}. Independent loopback SMB2 required bit: {n.get('signing_required', 'not collected')}; SecurityMode: {n.get('security_mode', 'not collected')}."
        elif r['id'] == 'SAL-02':
            def changes(path):
                return '; '.join(line for line in (path/'ad-manual.txt').read_text().splitlines() if line.startswith(('SELF_CHANGE_RC=', 'RAPID_CHANGES_ALLOWED=')))
            detail = '**Observed account proof:** baseline: ' + changes(baseline_path) + '. Latest: ' + changes(current_path) + '. Temporary account deletion is confirmed in each raw log.'
        else:
            def transports(path):
                d = json.loads((path/'http-manual.json').read_text())
                return '; '.join(f"{x['url']} => {x['status']}" for x in d['http']+d['https'])
            detail = '**Observed transport proof:**\n\nBefore: ' + transports(baseline_path) + '.\n\nAfter: ' + transports(current_path) + '.'
        sections.append((f"## {r['id']} - {r['title']}",
                         f"**{r['severity']} | {r['status']} | {r['asset']}**\n\n"
                         f"{r['risk']}\n\n{r['rating']}\n\n**Manual verification:** {r['verification']}\n\n"
                         f"{detail}\n\n{proof}\n\n**Remediation:** {r['remediation']}\n\n"
                         f"**Before:** control passed = {baseline['controls'][r['control']]}. "
                         f"**After:** control passed = {current['controls'][r['control']]}."))
    sections.extend([
        ('## Positive controls and analyst interpretation',
         'Finance access must deny bob while permitting alice; guest access is tested independently for Public, Finance and Scans. '
         'Company-wide authenticated Public access is intentional, not a world-readable vulnerability. '
         'AD complexity, history, lockout settings, privileged group membership and raw domain/OU SDDL are preserved for review. '
         'An ACL listing alone is not an exhaustive effective-permission analysis. '
         'CUPS anonymous /admin returns an authentication challenge. wg-easy and Kuma login panels do not by themselves prove auth bypass. '
         'No successful default-password login or anonymous administrative change is claimed.'),
        ('## Remediation, rollback and residual risk',
         'See [change record](../docs/remediation.md) and [manual procedure](../docs/manual-verification.md). '
         'Changes are persisted in the homelab Compose/configuration files, not just running containers. '
         'Rerun from a clean clone after starting the homelab. The local CA public certificate is safe to publish; its private key stays in a Docker volume. '
         'Do not install this learning-lab CA globally unless you understand that trust decision. The client checks use an explicit CA file. '
         'Template header observations and internal HTTP remain follow-up hardening opportunities; closed findings have the limited closure criteria stated above.'),
        ('## Honest limits', LIMITS),
        ('## Version review and follow-up', version_review),
        ('## Appendix A - asset inventory', (current_path / 'inventory.md').read_text().replace('# Live asset inventory\n', '')),
        ('## Appendix B - scanner observations', '\n'.join(f"- `{m['template']}` / {m['severity']}: {m['matched']}" for m in matches) or 'No template matches.'),
        ('## Appendix C - raw evidence index',
         '\n'.join(f"- [{phase}/{p.name}](../evidence/{path.name}/{p.name})" for phase, path in [('baseline', baseline_path), ('latest', current_path)] for p in sorted(path.iterdir()) if p.is_file()) +
         '\n\nRaw Nmap XML/normal/grepable output, Nuclei JSONL, service proofs and SHA-256 manifests are linked above. '
         'These logs are collected at source without credential values, cookies, tokens or complete Docker inspect output.'),
        ('## References',
         '- [Nmap NSE categories](https://nmap.org/book/nse-usage.html)\n'
         '- [Nuclei source and CLI](https://github.com/projectdiscovery/nuclei)\n'
         '- [Community templates pinned source](https://github.com/projectdiscovery/nuclei-templates/tree/17f5725dc10ced09f464dd2d255c19957aad51e7)\n'
         '- [Samba smb.conf](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html)\n'
         '- [Samba samba-tool](https://www.samba.org/samba/docs/current/man-html/samba-tool.8.html)\n'
         '- [Caddy internal TLS](https://caddyserver.com/docs/caddyfile/directives/tls)')])
    markdown = '\n\n'.join(title + '\n\n' + body for title, body in sections) + '\n'
    (output / 'security-assessment.md').write_text(markdown, encoding='utf-8')
    (output / 'findings.json').write_text(json.dumps({'summary': summary, 'findings': rows, 'baseline': baseline['run_id'], 'current': current['run_id']}, indent=2), encoding='utf-8')
    pdf(sections, rows, output / 'security-assessment.pdf')
    def html_inline(text):
        text = escape(text)
        text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
        text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
        def link(m):
            url = m.group(2)
            if url.startswith('../'): url = 'https://github.com/iamnajib71/security-assessment-lab/blob/main/' + url[3:]
            return '<a href="' + url + '">' + m.group(1) + '</a>'
        return re.sub(r'\[([^\]]+)\]\(([^)]+)\)', link, text)
    chunks = []
    for title, body in sections:
        level = 1 if title.startswith('# ') else 2
        chunks.append(f'<h{level}>' + escape(title.lstrip('# ')) + f'</h{level}>')
        for para in body.split('\n\n'):
            lines = para.splitlines()
            if lines and all(line.startswith('|') for line in lines):
                table_lines = [line for line in lines if not line.startswith('|---')]
                chunks.append('<div class="table-wrap"><table>')
                for i, line in enumerate(table_lines):
                    tag = 'th' if i == 0 else 'td'
                    chunks.append('<tr>' + ''.join(f'<{tag}>'+html_inline(c.strip())+f'</{tag}>' for c in line.strip('|').split('|')) + '</tr>')
                chunks.append('</table></div>')
            else:
                chunks.append('<p>' + html_inline(para).replace('\n', '<br>') + '</p>')
    html = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Homelab security assessment</title><style>body{max-width:1050px;margin:3rem auto;padding:0 1.5rem;font:16px/1.65 system-ui;color:#14273c;background:#f7f9fc}h1,h2{color:#123958;line-height:1.25}h2{margin-top:2.5rem}a{color:#135caa}code{font-size:.9em;background:#e8eef4;padding:.1em .3em}table{border-collapse:collapse;width:100%;font-size:.85em}td,th{padding:.75rem;text-align:left;vertical-align:top;border:1px solid #c8d5df}th{background:#dce8f0}.table-wrap{overflow-x:auto}p{overflow-wrap:anywhere}.download{padding:1rem;background:#e1f3eb}</style><p class="download"><a href="security-assessment.pdf">Download PDF</a> · <a href="https://github.com/iamnajib71/security-assessment-lab/tree/main/evidence">Raw evidence on GitHub</a></p>' + ''.join(chunks) + '</html>'
    (output / 'index.html').write_text(html, encoding='utf-8')
    return rows


def pdf(sections, rows, path):
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    styles = getSampleStyleSheet()
    styles['Normal'].fontSize = 9
    styles['Normal'].leading = 13
    styles['Normal'].spaceAfter = 7
    styles['Heading1'].textColor = colors.HexColor('#123958')
    styles['Heading2'].textColor = colors.HexColor('#123958')
    styles.add(ParagraphStyle('SmallCell', parent=styles['Normal'], fontSize=8, leading=11))
    story = []
    def inline(text):
        text = escape(text).replace('`', '')
        text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
        def link(m):
            url = m.group(2)
            if url.startswith('../'):
                url = 'https://github.com/iamnajib71/security-assessment-lab/blob/main/' + url[3:]
            return '<link href="' + url + '" color="#135caa">' + m.group(1) + '</link>'
        return re.sub(r'\[([^\]]+)\]\(([^)]+)\)', link, text)
    for title, body in sections:
        if title.startswith('## SAL-') or title.startswith('## Appendix A') or title.startswith('## Version review'):
            story.append(PageBreak())
        story.append(Paragraph(escape(title.lstrip('# ')), styles['Title'] if title.startswith('# ') else styles['Heading2']))
        if title == '## Findings register':
            data = [['ID', 'Severity', 'Finding', 'Status']]
            for r in rows:
                data.append([r['id'], r['severity'], r['title'], r['status']])
            data = [[Paragraph(escape(c), styles['SmallCell']) for c in row] for row in data]
            t = Table(data, colWidths=[49, 55, 275, 110], repeatRows=1)
            t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#dde8f0')),('VALIGN',(0,0),(-1,-1),'TOP'),('GRID',(0,0),(-1,-1),.3,colors.HexColor('#c5cfd8')),('BOTTOMPADDING',(0,0),(-1,-1),8)]))
            story.append(t)
        elif title == '## Appendix A - asset inventory':
            lines = [line for line in body.splitlines() if line.startswith('|') and not line.startswith('|---')]
            data = [[Paragraph(inline(c.strip()), styles['SmallCell']) for c in line.strip('|').split('|')] for line in lines]
            t = Table(data, colWidths=[70, 72, 48, 95, 204], repeatRows=1)
            t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#dde8f0')),('VALIGN',(0,0),(-1,-1),'TOP'),('LINEBELOW',(0,0),(-1,-1),.2,colors.HexColor('#d6e0e8')),('BOTTOMPADDING',(0,0),(-1,-1),6)]))
            story.append(t)
        else:
            for paragraph in body.split('\n\n'):
                # Preserve full text and URLs; long raw-index/table lines wrap in Paragraph.
                clean = inline(paragraph).replace('\n', '<br/>')
                story.append(Paragraph(clean, styles['Normal']))
        story.append(Spacer(1, 10))
    def footer(canvas, doc):
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.HexColor('#536779'))
        canvas.drawString(42, 26, 'Nazmul Hassan | Owner-authorized local homelab assessment')
        canvas.drawRightString(A4[0]-42, 26, f'{doc.page}')
    SimpleDocTemplate(str(path), pagesize=A4, rightMargin=42, leftMargin=42, topMargin=42, bottomMargin=45,
                      title='IT Support Homelab - Security Assessment', author='Nazmul Hassan').build(story, onFirstPage=footer, onLaterPages=footer)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--current', type=Path, required=True)
    ap.add_argument('--output', type=Path)
    a = ap.parse_args()
    generate(a.current, a.output)
