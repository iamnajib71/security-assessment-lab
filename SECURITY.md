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
