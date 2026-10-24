# SOC ticket 05 — Scheduled task registered on DC01

**Status:** Closed — authorised lab exercise; cleanup verified.

**Summary:** The administrator registered a future-dated SocLabDemo scheduled task on DC01, then removed it without execution.

**Severity:** Medium investigation priority (Wazuh level 8); benign lab disposition after review.

**ATT&CK mapping:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/). This is a monitoring hypothesis, not proof the technique was performed.

**Evidence:** Actual native agent alerts in [alerts.jsonl](../../evidence/monitoring/alerts.jsonl), corresponding [Windows XML](../../evidence/monitoring/windows-events.jsonl) and [integrity manifest](../../evidence/monitoring/manifest.json).

| Alert ID / ingestion time | Agent | Windows event / record | Source time |
|---|---|---|---|
| `1792814232.235999` / `2026-10-24T03:57:12.603+0000` | DC01 | 4698 / 24557 | 2026-10-24T03:57:12.0004414Z |
| `1792814282.317588` / `2026-10-24T03:58:02.750+0000` | DC01 | 4698 / 24583 | 2026-10-24T03:58:01.9721833Z |

**Assessment:** True positive for the event condition; benign, owner-authorised administration. No malicious incident is asserted. Repeated validation changes explain multiple alerts.

**Action taken:** Reviewed 4698 task XML, SYSTEM principal, whoami.exe action and future trigger. Postchecks confirm the task is absent.

[Actual cleanup checks](../../evidence/monitoring/DC01-cleanup-checks.json) retain domain membership, existing shares and Alex's enabled/unlocked state. [Collection provenance](../../evidence/monitoring/provenance.json) records the console method and buffering.

**Lesson:** A task-registration event is meaningful context, but approved maintenance also creates tasks. Examine executable, principal, trigger and change history.

**Regression check:** `python scripts/monitoring_evidence.py` rechecks the saved native alert against the current XML field conditions; CI also runs synthetic negative cases. The [Wazuh engine replay](../../evidence/monitoring/engine-tuning.json) separately verifies the share tuning against actual captured events.
