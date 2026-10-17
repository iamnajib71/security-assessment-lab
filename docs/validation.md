# Final clean-clone validation

Verified **18 October 2026, Australia/Sydney**, against the owner's local
`H:\My Projects - IT\it-support-homelab`. No external system was assessed.

A new clone of the public GitHub repository at source commit `3c3a385` was created
in `tmp/clean-clone/`. The README quick-start commands were followed without
reusing the development virtual environment:

| Check | Actual outcome |
|---|---|
| Create Python virtual environment; install requirements | Passed: ReportLab 4.4.9, Pillow 12.3.0 |
| Start homelab with `up -d --build --wait --wait-timeout 180` | Passed; directory rebuilt and healthy |
| Build scanner from Dockerfile | Passed with pinned engine/base images and community templates |
| Apply `scripts/remediate.py --lab ...` | Passed; existing hardening retained, all three HTTPS endpoints validated |
| Run `scripts/assess.py --lab ... --phase retest` | Passed; mandatory signing, AD minimum age and loopback TLS all true |
| Generate Markdown, PDF and HTML report | Passed from the new live run |
| Run unit tests | 14 tests passed |
| Verify evidence hashes and parsers | All five completed runs passed |

Raw clean-clone run: [20261017T134303Z-retest](../evidence/20261017T134303Z-retest/).
The final published report was regenerated in that clone and copied back with
the complete raw evidence directory. The source code was unchanged during this
validation; this record and the final run artifacts were then added to main.

The target homelab's support and AD regression scripts also returned **zero
failures** after hardening. See [latest support transcript](../evidence/regression/latest-homelab.txt)
and [latest AD transcript](../evidence/regression/latest-ad.txt).

The recorded demo is a separate real successful retest, retained with its original
terminal timing in `docs/demo.cast`. Historical evidence remains unchanged.
CI checks parsers, scope rejection, report generation, integrity and secret-file
exclusion without contacting the homelab. GitHub Pages publishes only the static
finished report; no live assessment endpoint is hosted.
