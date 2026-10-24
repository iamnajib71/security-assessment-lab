"""Submit one named request to the elevated lab helper; no arbitrary commands."""
from pathlib import Path
import argparse
import json
import time
import uuid

ROOT = Path(__file__).resolve().parents[1] / 'private/monitoring'
ACTIONS = ('Inspect', 'Start', 'StartDC', 'StartClient', 'SaveDC', 'SaveClient',
           'Firewall', 'Enroll', 'PrepareExercises', 'Exercise', 'Export', 'Cleanup')


def request(action):
    if action not in ACTIONS:
        raise ValueError('Unknown action')
    status = json.loads((ROOT / 'worker-status.json').read_text(encoding='utf-8-sig'))
    if not status['ready'] or (ROOT / 'request.json').exists():
        raise ValueError('Worker unavailable or busy')
    job = str(uuid.uuid4())
    pending = ROOT / f'{job}.pending'
    pending.write_text(json.dumps({'id': job, 'action': action}))
    pending.rename(ROOT / 'request.json')
    result = ROOT / f'{job}.json'
    until = time.monotonic() + 240
    while time.monotonic() < until:
        if result.exists():
            value = json.loads(result.read_text(encoding='utf-8-sig'))
            print(json.dumps(value))
            if not value['success']:
                raise SystemExit(1)
            return
        time.sleep(2)
    raise SystemExit(f'Request {job} pending. Inspect before retrying.')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=ACTIONS)
    request(p.parse_args().action)
