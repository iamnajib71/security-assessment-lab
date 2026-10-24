# SOC ticket 02 — Fictional account locked out

**Status:** Closed — authorised lab exercise; cleanup verified.

**Summary:** Five fixed deliberately wrong values were submitted at CLIENT01’s sign-in screen for soc.lockout, under owner authorisation.

**Severity:** Medium investigation priority (Wazuh level 8); benign lab disposition after review.

**ATT&CK mapping:** [T1110.001](https://attack.mitre.org/techniques/T1110/001/). This is a monitoring hypothesis, not proof the technique was performed.

**Evidence:** Actual native agent alerts in [alerts.jsonl](../../evidence/monitoring/alerts.jsonl), corresponding [Windows XML](../../evidence/monitoring/windows-events.jsonl) and [integrity manifest](../../evidence/monitoring/manifest.json).

| Alert ID / ingestion time | Agent | Windows event / record | Source time |
|---|---|---|---|
| `1792816885.375552` / `2026-10-24T04:41:25.259+0000` | DC01 | 4740 / 24967 | 2026-10-24T04:36:45.7120805Z |

**Assessment:** True positive for the event condition; benign, owner-authorised administration. No malicious incident is asserted. Repeated validation changes explain multiple alerts.

**Action taken:** Stopped at the five-submission cap. AD reported LockedOut=True and badPwdCount=5. Caller CLIENT01 was confirmed in 4740 TargetDomainName. The dedicated account was removed after evidence capture.

[Actual cleanup checks](../../evidence/monitoring/DC01-cleanup-checks.json) retain domain membership, existing shares and Alex's enabled/unlocked state. [Collection provenance](../../evidence/monitoring/provenance.json) records the console method and buffering.

**Lesson:** The 4740 XML caller field is TargetDomainName in this schema. UI failure text alone does not prove lockout. One earlier blank attempt affected fictional alex.morgan during navigation; Alex remained enabled and unlocked.

**Regression check:** `python scripts/monitoring_evidence.py` rechecks the saved native alert against the current XML field conditions; CI also runs synthetic negative cases. The [Wazuh engine replay](../../evidence/monitoring/engine-tuning.json) separately verifies the share tuning against actual captured events.
