# Scope and authorization

**All targets are my own homelab; testing performed by the owner.**

This repository assesses only `iamnajib71/it-support-homelab`, running locally.
Only current `it-support-homelab` Compose containers for Samba AD, Samba files,
CUPS, wg-easy and Uptime Kuma on `office-lan` (`172.20.0.0/16`) and the fixed
Docker-host loopback ports are authorized. An address being private is not enough.
The scanner refuses other identities, IPs, hostnames, CIDRs and non-loopback
publications. A local TLS proxy is introduced only as remediation.

No internet targets, third-party systems, denial of service or destructive
exploits. No credential cracking; credential checks are limited to fictional
homelab users and a temporary fictional verification account. Do not point this
tool at any other environment.

Never commit passwords, API keys, session cookies, private certificates/keys,
Docker inspect dumps or `.env`. The runner collects only non-secret fields at
source; fictional names, lab IPs and command output remain unredacted. A public
CA certificate is safe to export; its key stays in its Docker volume.

If reporting a problem through Issues, include a minimal reproduction without
credentials or private data. This project is a learning lab with no production
support promise.

## Defender extension

Defender collection additionally authorises only the owner's existing
`H:\My Projects - IT\windows-ad-lab` DC01 and CLIENT01 on
`WindowsADLab-Internal` / `corp.lab`. This does not expand the assessment scanner's
target list. Docker collection is limited to the four explicitly named services
under the existing `it-support-homelab` path and `office-lan` network.

No internet targets, third-party systems, exploits, password guessing or denial
of service are permitted. All event exercises use ordinary administration on
fictional accounts. The console test uses only CLIENT01, a fixed wrong test
value and five capped submissions under owner authorisation. There is no
credential search or failed-authentication API loop. Active response is off.

Host, guest, source-container, ingress and resource guards are described in
[the defender safety contract](docs/monitoring.md#ownership-and-safety-contract).
Credentials remain in ignored `.env` and DPAPI storage. Never commit `.env`,
local tool configuration files, API keys, browser cookies or private certificates.
