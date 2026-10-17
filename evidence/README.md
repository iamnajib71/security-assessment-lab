# Evidence provenance

**All targets are my own homelab; testing performed by the owner.**

Each timestamped run contains raw Nmap output, raw Nuclei findings JSONL,
normalized inventory/results, manual service proofs, and a SHA-256 manifest.
Run IDs and tool timestamps are UTC; narrative dates use Australia/Sydney.
Fictional usernames, private lab IPs, policy and ACL output are unredacted.
Credentials, session cookies and Docker environment dumps are never collected.
Nuclei's `-omit-raw` prevents collecting response cookies; it does not remove
fictional account or network data. No scanner API key or cloud upload is used.

`20261017T034611Z-baseline` is the completed pre-remediation assessment.
The first attempt failed at a Windows/Linux stdin newline boundary after its
scans; incomplete development artifacts are excluded from published evidence.

`20261017T035009Z-retest` is preserved unchanged as an intermediate retest.
It correctly showed mandatory signing in Nmap/configuration, but its initial
closure check incorrectly expected `smbclient signing=disabled` to refuse the
connection. That client still honors mandatory server signing. We corrected the
closure check to require the actual SMB2 NEGOTIATE required bit plus successful
signed access; no target control was weakened to produce a desired result.

The report selects the first completed baseline and its explicitly chosen latest
run. Earlier raw runs remain auditable. A report showing three closed findings
does not mean the entire homelab is vulnerability-free.

`regression/` contains the homelab's original before/after support and AD test
transcripts. Those scripts omit secret values at source. `version-reference.json`
contains official release metadata fetched as reference material, not scans of
internet targets. Synthetic parser fixtures are kept only in `tests/fixtures/`
and are never used to generate live assessment results.
