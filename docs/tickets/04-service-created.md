# SOC ticket 04 — Service installed on DC01

**Status:** Closed — authorised lab exercise; cleanup verified.

**Summary:** The administrator registered the demand-start SocLabDemo service on DC01, then deleted it without starting it.

**Severity:** Medium investigation priority (Wazuh level 8); benign lab disposition after review.

**ATT&CK mapping:** [T1543.003](https://attack.mitre.org/techniques/T1543/003/). This is a monitoring hypothesis, not proof the technique was performed.

**Evidence:** Actual native agent alerts in [alerts.jsonl](../../evidence/monitoring/alerts.jsonl), corresponding [Windows XML](../../evidence/monitoring/windows-events.jsonl) and [integrity manifest](../../evidence/monitoring/manifest.json).

| Alert ID / ingestion time | Agent | Windows event / record | Source time |
|---|---|---|---|
| `1792814232.233089` / `2026-10-24T03:57:12.603+0000` | DC01 | 4697 / 24556 | 2026-10-24T03:57:11.6024431Z |
| `1792814232.246338` / `2026-10-24T03:57:12.619+0000` | DC01 | 7045 / 1543 | 2026-10-24T03:57:11.5995261Z |
| `1792814282.312610` / `2026-10-24T03:58:02.734+0000` | DC01 | 7045 / 1544 | 2026-10-24T03:58:01.7185121Z |
| `1792814282.314678` / `2026-10-24T03:58:02.734+0000` | DC01 | 4697 / 24582 | 2026-10-24T03:58:01.7271667Z |

**Assessment:** True positive for the event condition; benign, owner-authorised administration. No malicious incident is asserted. Repeated validation changes explain multiple alerts.

**Action taken:** Reviewed the image path, service name and startup type. Postchecks confirm the service is absent. Security 4697 and System 7045 can both describe the same installation.

[Actual cleanup checks](../../evidence/monitoring/DC01-cleanup-checks.json) retain domain membership, existing shares and Alex's enabled/unlocked state. [Collection provenance](../../evidence/monitoring/provenance.json) records the console method and buffering.

**Lesson:** Count alerts separately from incidents; two event channels can report one benign change.

**Regression check:** `python scripts/monitoring_evidence.py` rechecks the saved native alert against the current XML field conditions; CI also runs synthetic negative cases. The [Wazuh engine replay](../../evidence/monitoring/engine-tuning.json) separately verifies the share tuning against actual captured events.
