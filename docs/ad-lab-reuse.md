# Reuse of the existing Windows AD lab

Inspected the existing `windows-ad-lab` repository and live VM definitions on
24 October 2026 (Australia/Sydney). The lab can be reused. No Windows install,
forest creation, VM recreation, domain join or credential replacement is needed.

| Existing component | Evidence/source in the AD lab | How monitoring reuses it |
|---|---|---|
| DC01 / CLIENT01 | `docs/current-state.md`; actual Hyper-V name/switch/disk preflight | Keep the existing guest OS and domain; add agents only |
| `corp.lab`, CORP and isolated network | `config/lab.psd1`; WindowsADLab-Internal; DC `.10`; client historical DHCP `.100` | Validate VM identity and domain; discover the current client address before firewall configuration |
| Protected credentials | Ignored `.lab/credentials/dc.xml` | Import locally through Windows DPAPI inside the elevated helper; never export or commit passwords |
| Resource guards | `scripts/host/Start-Lab.ps1` | Retain existing free-memory/disk checks; start one guest at a time when the combined start lacks headroom |
| Password/lockout baseline | `Initialize-LabDomain.ps1`; server acceptance checks | Keep the threshold and domain policy; create separate fictional SOC accounts |
| Share permissions | `Initialize-LabShares.ps1`; department groups, ABE and access checks | Preserve department shares; use an isolated SocRestricted exercise share |
| Account operations | `src/Lab.Identity.psm1` and identity scripts | Reuse the domain/scope principles; existing helpers intentionally reject our separate SOC OU, so do not weaken their guard |
| Regression checks | `acceptance/Server.Acceptance.Tests.ps1`, `Client.Acceptance.Tests.ps1` | Rerun relevant checks after monitoring where practical, distinguishing mocked tests from guest checks |
| Evidence capture | `scripts/host/Export-LabConsole.ps1` | Reuse read-only framebuffer capture if needed; do not regenerate or relabel historical screenshots |

The historical lockout ticket was an automated DC01 authentication exercise
for `alex.morgan`, with caller DC01. It is **not** reused as proof of the new
owner-authorised CLIENT01 login-screen exercise. That new scenario requires a fresh
4740 event, caller CLIENT01, the dedicated `soc.lockout` account and a real
Wazuh alert. The owner later authorised console input through the Hyper-V
virtual keyboard, bounded at five submissions with screen inspection. No old
authentication loop is called by this project; the new method and its incidental
blank Alex attempt are recorded in the defender evidence.

The AD lab's recorded 10 server and 6 standard-user acceptance checks describe
its existing deployment, not acceptance of Wazuh. The source folder and its
historical evidence are read-only dependencies for this extension.
