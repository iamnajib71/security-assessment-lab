# SOC ticket 03 — Disabled fictional account sign-in

**Status:** Closed — authorised lab exercise; cleanup verified.

**Summary:** One ordinary Run As attempt used the known password for the disabled fictional soc.disabled account.

**Severity:** Medium investigation priority (Wazuh level 7); benign lab disposition after review.

**ATT&CK mapping:** [T1078](https://attack.mitre.org/techniques/T1078/). This is a monitoring hypothesis, not proof the technique was performed.

**Evidence:** Actual native agent alerts in [alerts.jsonl](../../evidence/monitoring/alerts.jsonl), corresponding [Windows XML](../../evidence/monitoring/windows-events.jsonl) and [integrity manifest](../../evidence/monitoring/manifest.json).

| Alert ID / ingestion time | Agent | Windows event / record | Source time |
|---|---|---|---|
| `1792816974.460469` / `2026-10-24T04:42:54.970+0000` | CLIENT01 | 4625 / 4252 | 2026-10-24T03:44:56.6775714Z |

**Assessment:** True positive for the event condition; benign, owner-authorised administration. No malicious incident is asserted. Repeated validation changes explain multiple alerts.

**Action taken:** Verified subStatus 0xc0000072 rather than treating every 4625 as a bad password. The account stayed disabled and was later deleted.

[Actual cleanup checks](../../evidence/monitoring/DC01-cleanup-checks.json) retain domain membership, existing shares and Alex's enabled/unlocked state. [Collection provenance](../../evidence/monitoring/provenance.json) records the console method and buffering.

**Lesson:** A disabled sign-in is an investigation clue, not successful valid-account abuse. Rule 110108 is the substatus variant of this detection.

**Regression check:** `python scripts/monitoring_evidence.py` rechecks the saved native alert against the current XML field conditions; CI also runs synthetic negative cases. The [Wazuh engine replay](../../evidence/monitoring/engine-tuning.json) separately verifies the share tuning against actual captured events.
