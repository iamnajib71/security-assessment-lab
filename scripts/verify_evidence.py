"""Integrity and secret-leak gate for committed evidence (network free)."""
from pathlib import Path
import json
from report import load_run
from core import parse_nmap, parse_nuclei

root = Path(__file__).resolve().parents[1]
runs = sorted(p for p in (root / 'evidence').iterdir() if (p / 'checks.json').exists())
if not runs:
    raise SystemExit('No completed evidence runs')
for run in runs:
    result = load_run(run)
    scope = result['scope']
    inventory = parse_nmap((run / 'services.xml').read_text(), scope)
    parse_nuclei((run / 'nuclei.jsonl').read_text(), scope)
    if len(inventory) != 5:
        raise SystemExit('Incomplete scan inventory')
    print(run.name, 'hashes and parsers OK')
print(f'{len(runs)} real assessment runs verified')
