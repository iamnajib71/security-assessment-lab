# SOC ticket 07 — Restricted lab share access denied

**Status:** Closed — authorised lab exercise; cleanup verified.

**Summary:** A standard PowerShell mapping/read with valid soc.share credentials was denied by the SocRestricted share ACL.

**Severity:** Medium investigation priority (Wazuh level 6); benign lab disposition after review.

**ATT&CK mapping:** [T1039](https://attack.mitre.org/techniques/T1039/). This is a monitoring hypothesis, not proof the technique was performed.

**Evidence:** Actual native agent alerts in [alerts.jsonl](../../evidence/monitoring/alerts.jsonl), corresponding [Windows XML](../../evidence/monitoring/windows-events.jsonl) and [integrity manifest](../../evidence/monitoring/manifest.json).

| Alert ID / ingestion time | Agent | Windows event / record | Source time |
|---|---|---|---|
| `1792816885.384365` / `2026-10-24T04:41:25.352+0000` | DC01 | 5145 / 25010 | 2026-10-24T04:37:52.1093305Z |

**Assessment:** True positive for the event condition; benign, owner-authorised administration. No malicious incident is asserted. Repeated validation changes explain multiple alerts.

**Action taken:** Confirmed Audit Failure 5145, the restricted share and the fictional user. Permissions were retained; the isolated exercise share/account were removed after capture.

[Actual cleanup checks](../../evidence/monitoring/DC01-cleanup-checks.json) retain domain membership, existing shares and Alex's enabled/unlocked state. [Collection provenance](../../evidence/monitoring/provenance.json) records the console method and buffering.

**Lesson:** The broad saved-event replay alerted on 41 authorised successes and one denial. Failure-only tuning retained the denial. Share-level 5145 failure does not establish an NTFS-only denial.

**Regression check:** `python scripts/monitoring_evidence.py` rechecks the saved native alert against the current XML field conditions; CI also runs synthetic negative cases. The [Wazuh engine replay](../../evidence/monitoring/engine-tuning.json) separately verifies the share tuning against actual captured events.
