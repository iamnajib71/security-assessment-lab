# Security Assessment Lab

I assessed my own simulated office services, fixed verified security weaknesses and retested them while checking that staff access and support tasks still worked.

![Actual assessment and before/after evidence review](docs/demo.gif)

[![CI](https://github.com/iamnajib71/security-assessment-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/iamnajib71/security-assessment-lab/actions/workflows/ci.yml) · [MIT licence](LICENSE)

## At a glance

| Area | Evidence-backed summary |
| --- | --- |
| **The problem** | An office administrator can expose account and file-management services through weak settings; staff access and administration then carry avoidable security risk, while careless fixes can disrupt support. This exercise uses only my owned homelab. |
| **What I built** | I scoped the assessment, verified scanner observations with service checks, applied targeted hardening and published a report with raw before/after evidence. |
| **Results** | [3 verified findings fixed and retested, with 0 open confirmed findings](report/security-assessment.md); [14 unit tests passed and support/directory regressions reported zero failures](docs/validation.md). This is a bounded lab assessment. |
| **Skills shown** | Security assessment, Nmap, Nuclei, vulnerability validation, SMB, Active Directory, Python, remediation, regression testing and technical reporting. |
| **Relevant roles** | Junior Security Analyst, Vulnerability Analyst, IT Support Analyst, Junior Systems Administrator. |
| **How it was built** | Designed, specified and reviewed by me; built with Codex as my coding agent (vibe coding). Verification and its limits are linked below. |
| **Try it / evidence** | [Sample report](https://iamnajib71.github.io/security-assessment-lab/) · [PDF report](report/security-assessment.pdf) · [Raw evidence](evidence/) · [Quick start](#quick-start) |

## What I did, step by step

1. Confirmed ownership and limited the target list to the [explicitly allowed homelab services](SECURITY.md).
2. Captured the baseline with bounded scans and authenticated checks, preserving the [raw evidence and provenance](evidence/README.md).
3. Distinguished informational scanner observations from verified findings and explained their practical impact in the [report](report/security-assessment.md).
4. Hardened file-service signing, directory password policy and local administration transport; recorded the [change and rollback procedures](docs/remediation.md).
5. Retested each finding and reran support and directory workflows to detect regressions.
6. Repeated the documented commands from a clean public clone and published the [validation record](docs/validation.md).

## Problems I hit and how I solved them

- **The initial signing check gave a misleading result:** a client preference still allowed mandatory signing, so I replaced that closure check with the actual negotiation required bit plus signed access. [Preserved intermediate evidence](evidence/README.md).
- **The first assessment stopped at a Windows/Linux newline boundary:** retained only completed runs as published evidence and documented the failed attempt. [Provenance](evidence/README.md).
- **Hardening could break routine support:** reran the existing support and directory tests after remediation; both recorded zero failures. [Validation and transcripts](docs/validation.md).

## Scope and authorization

> **All targets are my own homelab; testing performed by the owner, Nazmul Hassan.**
>
> Only [my IT Support Homelab](https://github.com/iamnajib71/it-support-homelab): Samba AD, Samba file server, CUPS, wg-easy, Uptime Kuma and the Docker host's fixed `127.0.0.1` lab ports. The Compose network is `office-lan`, `172.20.0.0/16`.
>
> No internet targets, third-party systems, live credential cracking outside fictional homelab accounts, denial of service or destructive exploits. This is a learning assessment, not a red-team engagement.

The runner derives **five exact IPs** from current Compose labels and network membership. A private IP is never enough: arbitrary addresses, hostnames and CIDRs are refused. Nmap uses those exact IPs, not a `/16` sweep. A scanner-container firewall allows only those five destinations and blocks IPv6. No Docker socket or credentials are mounted into the scanner. Loopback requests use a fixed address/port allow-list, ignore system proxies and reject external redirects. [Safety contract](SECURITY.md).

Tool/template downloads are setup traffic, not internet testing. Homepage is supporting infrastructure and is not scanned. The local TLS proxy is a remediation control checked through the original loopback admin ports.

## Architecture

```mermaid
flowchart LR
    O[Owner / Windows Python runner] --> V[Validate Compose labels + office-lan membership]
    V --> S[Nmap + Nuclei scanner container<br/>exact IP egress allow-list]
    subgraph LAB[Owned homelab / office-lan 172.20.0.0/16]
        F[Samba file server]
        A[Samba AD / ITOPS.LAB]
        P[CUPS]
        W[wg-easy]
        K[Uptime Kuma]
        T[Caddy local TLS proxy]
    end
    S --> F & A & P & W & K
    O -->|fixed 127.0.0.1 ports / HTTPS| T
    T --> P & W & K
    O -->|authenticated checks / fictional users| F & A
    S --> E[Raw evidence + SHA-256 manifests]
    O --> E
    E --> R[Markdown + PDF + static sample report]
    C[GitHub Actions / synthetic parser fixtures] --> R
```

## Findings summary

[Published assessment evidence](report/security-assessment.md). Baseline: **17 October 2026**; latest retest: **18 October 2026 (Australia/Sydney)**. **5 service hosts; 3 verified findings; 1 Medium, 2 Low; 3 fixed and retested; 0 open confirmed findings.** Informational scanner observations and residual risks are separate from that count.

| ID | Asset | Severity | Verified finding | Status |
|---|---|---|---|---|
| SAL-01 | Samba file server | Medium | SMB signing optional | Fixed - retested |
| SAL-02 | Samba AD | Low | Minimum password age zero permits rapid changes | Fixed - retested |
| SAL-03 | wg-easy / Kuma / CUPS loopback administration | Low | Plaintext HTTP administration (one grouped root cause) | Fixed - retested |

The baseline Nuclei scan returned **20 informational matches**, not 20 vulnerabilities. Public login panels and authenticated company-wide shares are not treated as auth bypasses. Guest share reads and Bob's Finance access were denied. Generated fictional-user credentials were not weak/common defaults. Ratings are **CVSS-style qualitative priorities**, with local prerequisites and limits explained; no invented numeric CVSS scores or unverified CVE claims.

## Before and after: SMB signing

| Proof | Before | After |
|---|---|---|
| Live Nmap `smb2-security-mode` | `Message signing enabled but not required` | `Message signing enabled and required` |
| Persistent fileserver configuration | Signing optional | `server signing = required` |
| Independent SMB2 negotiation | Baseline policy recorded by Nmap | Required bit set (`SecurityMode = 3`) |
| Service health | Alice allowed; Bob denied Finance | Signed Alice access works; Bob still denied |

The original `smbclient signing=disabled` preference still connected after hardening because this client honors mandatory server signing. That was **not** an unsigned-session bypass. The final retest reads the actual SMB2 negotiation bit and checks signed access. [Evidence provenance](evidence/README.md) preserves the intermediate result and correction.

Other fixes persist a one-day AD minimum password age and TLS on the same loopback admin ports, using an explicit local CA. Internal Compose-network HTTP remains a residual risk. The homelab's support and AD regression suites both pass with **zero failures** before and after. [Change record and rollback](docs/remediation.md).

## Quick start

Requires Windows PowerShell, Python **3.12+**, Docker Desktop with Linux containers, and your already-provisioned **owned** `it-support-homelab` at the path below. Bootstrap that dependency using [its README](https://github.com/iamnajib71/it-support-homelab#run-it) first. Existing data volumes and generated credentials are retained. No paid tools or API keys.

Run from a new clone in PowerShell:

```powershell
git clone https://github.com/iamnajib71/security-assessment-lab.git
cd security-assessment-lab
$Lab = 'H:\My Projects - IT\it-support-homelab'
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
docker compose --project-directory $Lab up -d --build --wait --wait-timeout 180
docker build -t security-assessment-scanner:1 .
.\.venv\Scripts\python.exe scripts/remediate.py --lab $Lab
.\.venv\Scripts\python.exe scripts/assess.py --lab $Lab --phase retest
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe scripts/verify_evidence.py
```

Open `report/security-assessment.md` or `report/security-assessment.pdf`. Each run writes a new timestamped `evidence/` directory. Nothing is uploaded by the assessment. The published sample is static; no live scanner is hosted.

These commands passed from a fresh GitHub clone on 18 October 2026: [validation record and raw run](docs/validation.md).

`scripts/remediate.py` applies only the three documented hardening changes to the owned lab and updates its PowerShell HTTP checks to validate the explicit local CA. It is safe to repeat and never seeds vulnerable settings. Local backups are ignored in `private/`. Browser trust is a separate choice; CLI checks use the exported public CA without `--insecure`.

For the standard sibling layout, `make assess` or `python scripts/assess.py --phase retest` runs recon → scan → checks → report after the scanner image is built. On an **unmodified** owned homelab, use `--phase baseline` before remediation to capture your own before state. Never weaken a fixed lab just to replay the demonstration. Existing historical evidence is retained and clearly dated.

Nuclei is used instead of Greenbone because four pinned, reviewed community GET templates make a lightweight, repeatable local pass. It runs unauthenticated; SMB/AD and the homelab regression checks supply authenticated coverage. [Template selection and limits](templates/README.md).

## Project structure

```text
scripts/           scope validation, live runner, remediation, parsers, report + demo tools
templates/         four pinned community templates + upstream licence
evidence/          actual scans, inventories, manual proofs, integrity manifests
report/            Markdown, PDF, normalized findings, static HTML sample
docs/              manual procedure, change record, source patch, demo, social card
tests/fixtures/    explicitly synthetic parser data; never live evidence
.github/workflows/ fixture/unit/report CI and static report publication
```

## Honest limits

- Owner-performed, small self-assessed lab with known tools; **not evidence of paid penetration testing, OSCP-level exploitation, or production SOC/incident-response experience**.
- Five service containers; top 1,000 TCP ports plus the known wg-easy admin port and fixed loopback ports. No UDP sweep, broad CVE coverage, destructive exploits, password cracking or AD attack-chain validation.
- Four Nuclei templates are deliberately narrow. No matches would not mean “secure”; header/panel matches do not establish compromise.
- Samba AD is not Windows Server. Group/SDDL review is not exhaustive effective-ACL or GPO analysis. Rapid changes were demonstrated; a full password-history bypass was not.
- Loopback TLS is fixed; HTTP inside `office-lan` remains. Local CA trust is explicit. Docker/host administrators remain privileged.
- Older image/release tracks need compatibility and patch review. Nmap's Samba version guess differed from `smbd --version`; runtime evidence takes precedence. No version-only CVE finding is asserted. [Official release references](evidence/version-reference.json).
- Original lab constraints still apply: separate Samba/AD accounts, simulated laser printer, no production VPN deployment or implemented scheduled backups.

## Built by Nazmul Hassan

[LinkedIn](https://www.linkedin.com/in/iamnajib71) · [GitHub](https://github.com/iamnajib71)
