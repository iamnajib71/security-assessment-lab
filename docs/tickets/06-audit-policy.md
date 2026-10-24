# SOC ticket 06 — Audit policy changed on DC01

**Status:** Closed — authorised lab exercise; cleanup verified.

**Summary:** The administrator enabled additional Other Logon/Logoff auditing, then restored the saved exercise policy.

**Severity:** Medium investigation priority (Wazuh level 8); benign lab disposition after review.

**ATT&CK mapping:** [T1562.002](https://attack.mitre.org/techniques/T1562/002/). This is a monitoring hypothesis, not proof the technique was performed.

**Evidence:** Actual native agent alerts in [alerts.jsonl](../../evidence/monitoring/alerts.jsonl), corresponding [Windows XML](../../evidence/monitoring/windows-events.jsonl) and [integrity manifest](../../evidence/monitoring/manifest.json).

| Alert ID / ingestion time | Agent | Windows event / record | Source time |
|---|---|---|---|
| `1792814282.327927` / `2026-10-24T03:58:02.766+0000` | DC01 | 4719 / 24585 | 2026-10-24T03:58:02.1791853Z |
| `1792814282.330826` / `2026-10-24T03:58:02.781+0000` | DC01 | 4719 / 24586 | 2026-10-24T03:58:02.1948006Z |

**Assessment:** True positive for the event condition; benign, owner-authorised administration. No malicious incident is asserted. Repeated validation changes explain multiple alerts.

**Action taken:** Compared 4719 subcategory/change fields with the approved action. The exercise restored its own backup; required monitoring audits remain enabled.

[Actual cleanup checks](../../evidence/monitoring/DC01-cleanup-checks.json) retain domain membership, existing shares and Alex's enabled/unlocked state. [Collection provenance](../../evidence/monitoring/provenance.json) records the console method and buffering.

**Lesson:** Enabling auditing is benign here. The ATT&CK mapping describes potential impairment to investigate, not an attack performed by this lab.

**Regression check:** `python scripts/monitoring_evidence.py` rechecks the saved native alert against the current XML field conditions; CI also runs synthetic negative cases. The [Wazuh engine replay](../../evidence/monitoring/engine-tuning.json) separately verifies the share tuning against actual captured events.
