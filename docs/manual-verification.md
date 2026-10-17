# Supervised manual verification

All targets are the owner's `it-support-homelab`. These proofs were performed by
running commands locally and inspecting the actual output. The repeatable runner
captures the same bounded checks in each evidence run. No exploitation beyond
the stated proof, packet interception, relay, cracking or denial of service.

## SAL-01: optional SMB signing

From the homelab folder, open an interactive shell:

```powershell
docker compose exec fileserver sh
```

Inside that container (the password is read from its private environment):

```sh
export PASSWD="$SMB_ALICE_PASSWORD"
smbclient //127.0.0.1/Finance -U alice -c ls --option='client signing=disabled'
unset PASSWD
testparm -s --parameter-name='server signing'
```

The client preference is not sufficient to prove an unsigned session: this Samba
client still signs when the server requires it. We observed that behavior during
retest and do not claim its successful connection was unsigned.

Compare the baseline `smb2-security-mode` (enabled but not required) with the retest
(required), then independently read the actual SMB2 negotiation response:

```powershell
python scripts/smb_negotiate.py
```

The script sends one credential-free SMB2 NEGOTIATE to **127.0.0.1:1445 only**,
retains request/response hex and interprets the required bit. Retest requires
`signing_required: true` and successful authenticated access with
`client signing=required`. No data is changed by `ls` or negotiation.

## SAL-02: rapid password changes

```powershell
docker compose exec directory samba-tool domain passwordsettings show
```

The supervised proof in `scripts/assess.py` (`AD_CHECK`) creates **only** the
temporary fictional account `assessment_probe`, gives it a random strong
password, and uses `samba-tool user password` to perform two immediate
self-service changes as that user. Passwords are passed privately, never printed.
It refuses to replace an existing account and deletes its own account in `finally`.

Read `ad-manual.txt`: two `SELF_CHANGE_RC=0` values before; a failed immediate
change and `RAPID_CHANGES_ALLOWED=false` after. This proves rapid changes are
blocked. It does not claim a completed 12-password history bypass. Administrative
password resets are a separate workflow and are regression-tested afterward.

## SAL-03: plaintext admin transport

Before hardening, run these without credentials:

```powershell
curl.exe --noproxy '*' -i http://127.0.0.1:51821/
curl.exe --noproxy '*' -i http://127.0.0.1:13001/
curl.exe --noproxy '*' -i http://127.0.0.1:6631/admin/
```

Observe the unencrypted application responses and CUPS Basic authentication
challenge. Never supply passwords to these HTTP URLs for demonstration purposes.
After `scripts/remediate.py`, repeat and confirm plaintext no longer serves the
application. Then check real certificate validation:

```powershell
$ca = '../it-support-homelab/homelab/tls/lab-root.crt'
curl.exe --noproxy '*' --cacert $ca -i https://127.0.0.1:51821/
curl.exe --noproxy '*' --cacert $ca -i https://127.0.0.1:13001/
curl.exe --noproxy '*' --cacert $ca -i https://127.0.0.1:6631/admin/
```

Do not use `-k` / `--insecure`. The public CA certificate is exported; its private
key remains in Caddy's Docker volume. Application responses of 200 and a CUPS
401 challenge are expected. Host-facing HTTP is fixed; internal lab HTTP remains
an explicit residual risk. Browser CA trust is a separate local choice.
