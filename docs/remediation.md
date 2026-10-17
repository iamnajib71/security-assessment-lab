# Persistent remediation change record

Owner-authorized local changes, 17 October 2026 (Australia/Sydney).

| Finding | Persistent source change | Live action | Retest |
|---|---|---|---|
| SAL-01 | Add `-g "server signing = mandatory"` to fileserver command | Recreate fileserver, retain named volumes | SMB2 negotiation and Nmap require signing; signed alice succeeds; bob denied Finance |
| SAL-02 | `homelab/ad/seed.sh`: `--min-pwd-age=1` | `samba-tool domain passwordsettings set --min-pwd-age=1` | Immediate self-service change blocked; admin reset/lockout workflow works |
| SAL-03 | Remove three direct HTTP TCP publications; add loopback Caddy TLS service and `homelab/tls/Caddyfile` | Recreate affected services and start proxy; export public CA only | HTTP does not serve app; HTTPS validates at same ports |

Apply from this repository:

```powershell
python scripts/remediate.py --lab '../it-support-homelab'
python scripts/assess.py --phase retest
```

The script validates scope before mutation, fails on unexpected configuration,
does not introduce weaknesses, and retains original files under ignored
`private/pre-hardening/`. Rerunning preserves already-applied hardening.
`docs/homelab-hardening.patch` records the source diff against the original lab.
Existing generated passwords, accounts, peers, shares, queues and monitors stay
in their existing volumes. No `down -v` is used.

TLS endpoints keep their original port numbers and use `https://127.0.0.1`.
Use an explicit `--cacert ../it-support-homelab/homelab/tls/lab-root.crt` when testing.
The public certificate is not a credential. Private keys are never exported.
Internal monitoring continues to use HTTP on office-lan; no internet listener is added.

## Rollback

Stop `admin-tls`, restore the backed-up Compose, seed and two PowerShell test files, set
`--min-pwd-age=0` if intentionally reversing that policy, and `docker compose up -d`
the affected services. This reintroduces the documented weaknesses; use only for
a deliberate local rollback. Restore old admin URLs in documentation if rolling
back TLS. Never remove data volumes. The assessment tool
does not automatically weaken an already-fixed lab to recreate baseline evidence.

## Residual work

Consider end-to-end TLS inside the Compose network, immutable image digests,
broader patch/CVE validation, a dedicated management network, and effective AD
delegation analysis. Informational missing-header matches remain observations;
the report does not claim these follow-up items are fixed.
