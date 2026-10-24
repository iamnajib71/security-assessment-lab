# SOC ticket 01 — Privileged group membership added

**Status:** Closed — authorised lab exercise; cleanup verified.

**Summary:** A disabled fictional account was briefly added to Domain Admins during an approved administrative exercise.

**Severity:** High investigation priority (Wazuh level 10); benign lab disposition after review.

**ATT&CK mapping:** [T1098.007](https://attack.mitre.org/techniques/T1098/007/). This is a monitoring hypothesis, not proof the technique was performed.

**Evidence:** Actual native agent alerts in [alerts.jsonl](../../evidence/monitoring/alerts.jsonl), corresponding [Windows XML](../../evidence/monitoring/windows-events.jsonl) and [integrity manifest](../../evidence/monitoring/manifest.json).

| Alert ID / ingestion time | Agent | Windows event / record | Source time |
|---|---|---|---|
| `1792814232.230007` / `2026-10-24T03:57:12.589+0000` | DC01 | 4728 / 24552 | 2026-10-24T03:57:11.5860179Z |
| `1792814282.309528` / `2026-10-24T03:58:02.720+0000` | DC01 | 4728 / 24578 | 2026-10-24T03:58:01.7140212Z |

**Assessment:** True positive for the event condition; benign, owner-authorised administration. No malicious incident is asserted. Repeated validation changes explain multiple alerts.

**Action taken:** Verified the privileged group SID, member identity and approved retest times. Membership was removed in finally; the disabled probe account was later deleted.

[Actual cleanup checks](../../evidence/monitoring/DC01-cleanup-checks.json) retain domain membership, existing shares and Alex's enabled/unlocked state. [Collection provenance](../../evidence/monitoring/provenance.json) records the console method and buffering.

**Lesson:** Use the group SID rather than an English display name; keep the probe disabled during privilege tests.

**Regression check:** `python scripts/monitoring_evidence.py` rechecks the saved native alert against the current XML field conditions; CI also runs synthetic negative cases. The [Wazuh engine replay](../../evidence/monitoring/engine-tuning.json) separately verifies the share tuning against actual captured events.
