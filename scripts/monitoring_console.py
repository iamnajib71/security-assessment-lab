"""Request one fixed CLIENT01 console action; inspect each returned framebuffer."""
import argparse
import json
import contextlib
import io
from monitoring_request import ROOT, request

STEPS = ('Snapshot', 'SAS', 'Tab', 'Acknowledge', 'OtherUser', 'TypeUser', 'TypeWrong', 'Submit')

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('step', choices=STEPS)
    p.add_argument('--capture-path', action='store_true')
    args = p.parse_args()
    step = args.step
    (ROOT / 'console-request.json').write_text(json.dumps({'step': step}))
    if args.capture_path:
        with contextlib.redirect_stdout(io.StringIO()): request('StartClient')
        print(json.loads((ROOT / 'console-result.json').read_text(encoding='utf-8-sig'))['capture'])
    else:
        request('StartClient')
        print((ROOT / 'console-result.json').read_text(encoding='utf-8-sig'))
