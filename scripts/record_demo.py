"""Record a real terminal run as asciinema v2 and render a 60-second GIF.

Wall-clock timing is retained in demo.cast. Playback is accelerated to 60 seconds;
the on-screen label states that explicitly. No terminal output is invented.
"""
import json
import argparse
import os
from pathlib import Path
import subprocess
import sys
import time

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]


def font(size):
    for path in ['C:/Windows/Fonts/consola.ttf', '/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf']:
        if Path(path).exists(): return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--lab', type=Path, default=ROOT.parent/'it-support-homelab')
    args = ap.parse_args()
    docs = ROOT / 'docs'; docs.mkdir(exist_ok=True)
    events = []; start = time.monotonic()
    def emit(line):
        stamp = time.monotonic()-start
        events.append([stamp, 'o', line.rstrip()+'\r\n'])
        print(line.rstrip(), flush=True)
    emit('$ python scripts/assess.py --phase retest')
    p = subprocess.Popen([sys.executable, str(ROOT/'scripts/assess.py'), '--lab', str(args.lab), '--phase', 'retest'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8')
    for line in p.stdout: emit(line)
    if p.wait(): raise SystemExit('Actual assessment failed; demo not produced')
    data = json.loads((ROOT/'report/findings.json').read_text())
    emit('$ cat report/findings.json  # summary')
    emit(data['summary'])
    for run, label in [(data['baseline'], 'BEFORE'), (data['current'], 'AFTER')]:
        emit('$ read evidence/' + run + '/inventory.json  # fileserver signing mode')
        inventory = json.loads((ROOT/'evidence'/run/'inventory.json').read_text())
        for host in inventory:
            if host['asset'] == 'fileserver':
                for line in host['scripts'].get('smb2-security-mode', '').splitlines():
                    if 'Message signing enabled' in line: emit(label + ' fileserver: ' + line.strip())
    negotiate = json.loads((ROOT/'evidence'/data['current']/'smb-negotiate.json').read_text())
    emit('Independent SMB2 NEGOTIATE: SecurityMode=' + str(negotiate['security_mode']) + '; signing_required=' + str(negotiate['signing_required']))
    emit('Report generated: report/security-assessment.md + .pdf')
    duration = time.monotonic()-start
    header = {'version': 2, 'width': 110, 'height': 27, 'timestamp': int(time.time()-duration),
              'title': 'Real local homelab assessment and found-fixed-retested evidence',
              'env': {'SHELL': 'python', 'TERM': 'xterm-256color'}}
    (docs/'demo.cast').write_text('\n'.join(json.dumps(x) for x in [header, *events])+'\n', encoding='utf-8')
    frames = []
    import textwrap
    for second in range(60):
        # 42 seconds to show the live run, 18 seconds for the actual evidence review.
        cutoff = (second/42*duration) if second < 42 else duration+1
        lines = []
        for t, _, content in events:
            if t <= cutoff:
                for line in content.splitlines(): lines.extend(textwrap.wrap(line, 100, replace_whitespace=False) or [''])
        im = Image.new('RGB', (1200, 720), '#0a1726'); d = ImageDraw.Draw(im)
        d.rounded_rectangle((20,20,1180,700), radius=18, fill='#10263a', outline='#31516b', width=2)
        d.text((44,38), 'SECURITY ASSESSMENT LAB  |  ACTUAL LOCAL RUN', font=font(21), fill='#64e5be')
        d.text((44,76), f'Playback accelerated - original {duration:.0f}s; raw timing in docs/demo.cast', font=font(17), fill='#aec2d4')
        for i, line in enumerate(lines[-24:]): d.text((44,120+i*22), line, font=font(17), fill='#e2eaf2')
        frames.append(im)
    frames[0].save(docs/'demo.gif', save_all=True, append_images=frames[1:], duration=1000, loop=0, optimize=True)
    print('Actual 60-second demo GIF saved.')


if __name__ == '__main__': main()
