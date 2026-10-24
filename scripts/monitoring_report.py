"""Render the SOC record from verified captures; no invented tickets or counts."""
from datetime import datetime
import json

from soc_rules import ALIASES, CATALOG, ROOT, field, read_jsonl

EVIDENCE = ROOT / 'evidence/monitoring'

NOTES = {
 '110101': ('A disabled fictional account was briefly added to Domain Admins during an approved administrative exercise.',
             'Verified the privileged group SID, member identity and approved retest times. Membership was removed in finally; the disabled probe account was later deleted.',
             'Use the group SID rather than an English display name; keep the probe disabled during privilege tests.'),
 '110102': ('Five fixed deliberately wrong values were submitted at CLIENT01’s sign-in screen for soc.lockout, under owner authorisation.',
             'Stopped at the five-submission cap. AD reported LockedOut=True and badPwdCount=5. Caller CLIENT01 was confirmed in 4740 TargetDomainName. The dedicated account was removed after evidence capture.',
             'The 4740 XML caller field is TargetDomainName in this schema. UI failure text alone does not prove lockout. One earlier blank attempt affected fictional alex.morgan during navigation; Alex remained enabled and unlocked.'),
 '110103': ('One ordinary Run As attempt used the known password for the disabled fictional soc.disabled account.',
             'Verified subStatus 0xc0000072 rather than treating every 4625 as a bad password. The account stayed disabled and was later deleted.',
             'A disabled sign-in is an investigation clue, not successful valid-account abuse. Rule 110108 is the substatus variant of this detection.'),
 '110104': ('The administrator registered the demand-start SocLabDemo service on DC01, then deleted it without starting it.',
             'Reviewed the image path, service name and startup type. Postchecks confirm the service is absent. Security 4697 and System 7045 can both describe the same installation.',
             'Count alerts separately from incidents; two event channels can report one benign change.'),
 '110105': ('The administrator registered a future-dated SocLabDemo scheduled task on DC01, then removed it without execution.',
             'Reviewed 4698 task XML, SYSTEM principal, whoami.exe action and future trigger. Postchecks confirm the task is absent.',
             'A task-registration event is meaningful context, but approved maintenance also creates tasks. Examine executable, principal, trigger and change history.'),
 '110106': ('The administrator enabled additional Other Logon/Logoff auditing, then restored the saved exercise policy.',
             'Compared 4719 subcategory/change fields with the approved action. The exercise restored its own backup; required monitoring audits remain enabled.',
             'Enabling auditing is benign here. The ATT&CK mapping describes potential impairment to investigate, not an attack performed by this lab.'),
 '110107': ('A standard PowerShell mapping/read with valid soc.share credentials was denied by the SocRestricted share ACL.',
             'Confirmed Audit Failure 5145, the restricted share and the fictional user. Permissions were retained; the isolated exercise share/account were removed after capture.',
             'The broad saved-event replay alerted on 41 authorised successes and one denial. Failure-only tuning retained the denial. Share-level 5145 failure does not establish an NTFS-only denial.'),
}


def main():
    metrics = json.loads((EVIDENCE / 'metrics.json').read_text())
    tuning = json.loads((EVIDENCE / 'engine-tuning.json').read_text())
    alerts = read_jsonl(EVIDENCE / 'alerts.jsonl')
    tickets = ROOT / 'docs/tickets'
    tickets.mkdir(exist_ok=True)
    lines = ['# Monitoring acceptance, ATT&CK coverage and SOC metrics', '',
        f"Seven detection conditions produced **{metrics['total_detection_alerts']} actual native Wazuh alerts** from the two owned Windows agents. These are benign lab administrative events, not attacks or customer incidents.", '',
        f"Alert-ingestion window: `{metrics['first_ingestion']}` to `{metrics['last_ingestion']}`. Windows source times are preserved separately. Agents buffered events while the manager was off to reduce host memory pressure.", '',
        '| ATT&CK monitoring hypothesis | Data source | Rule | Offline field replay | Native alert tested | Triage |',
        '|---|---|---|---|---|---|']
    for row in CATALOG:
        rule = row['rule']
        selected = [a for a in alerts if ALIASES.get(str(a['rule']['id']), str(a['rule']['id'])) == rule]
        if not selected: raise ValueError(f'No native evidence for {rule}')
        tech = row['technique']
        link = 'https://attack.mitre.org/techniques/' + tech.replace('.', '/') + '/'
        lines.append(f"| [{tech}]({link}) — {row['name']} | {row['source']} | {rule}{' / 110108' if rule == '110103' else ''} | Yes | Yes | [{len(selected)} alert(s)](tickets/{row['ticket']}) |")
        summary, action, lesson = NOTES[rule]
        severity = 'High' if max(a['rule']['level'] for a in selected) >= 10 else 'Medium'
        evidence = ['| Alert ID / ingestion time | Agent | Windows event / record | Source time |', '|---|---|---|---|']
        for alert in selected:
            data = alert['data']
            evidence.append(f"| `{alert['id']}` / `{alert['timestamp']}` | {alert['agent']['name']} | {field(data,'win.system.eventID')} / {field(data,'win.system.eventRecordID')} | {field(data,'win.system.systemTime')} |")
        text = f"# SOC ticket {row['ticket'][:2]} — {row['name']}\n\n**Status:** Closed — authorised lab exercise; cleanup verified.\n\n**Summary:** {summary}\n\n**Severity:** {severity} investigation priority (Wazuh level {max(a['rule']['level'] for a in selected)}); benign lab disposition after review.\n\n**ATT&CK mapping:** [{tech}]({link}). This is a monitoring hypothesis, not proof the technique was performed.\n\n**Evidence:** Actual native agent alerts in [alerts.jsonl](../../evidence/monitoring/alerts.jsonl), corresponding [Windows XML](../../evidence/monitoring/windows-events.jsonl) and [integrity manifest](../../evidence/monitoring/manifest.json).\n\n" + '\n'.join(evidence) + f"\n\n**Assessment:** True positive for the event condition; benign, owner-authorised administration. No malicious incident is asserted. Repeated validation changes explain multiple alerts.\n\n**Action taken:** {action}\n\n[Actual cleanup checks](../../evidence/monitoring/DC01-cleanup-checks.json) retain domain membership, existing shares and Alex's enabled/unlocked state. [Collection provenance](../../evidence/monitoring/provenance.json) records the console method and buffering.\n\n**Lesson:** {lesson}\n\n**Regression check:** `python scripts/monitoring_evidence.py` rechecks the saved native alert against the current XML field conditions; CI also runs synthetic negative cases. The [Wazuh engine replay](../../evidence/monitoring/engine-tuning.json) separately verifies the share tuning against actual captured events.\n"
        (tickets / row['ticket']).write_text(text, encoding='utf-8')
    lines += ['', '## SOC metrics', '', '| Detection | Actual native alerts | Disposition |', '|---|---|---|']
    for row in CATALOG:
        lines.append(f"| {row['rule']} — {row['name']} | {metrics['per_detection'][row['rule']]} | Benign true positive |")
    lines += ['', f"{metrics['total_detection_alerts']} alerts cover 7 review conditions; alert counts are not incident counts. Native 4697/7045 and approved retests can create multiple alerts for a single type of change. Two native Sysmon process-event samples are retained separately and excluded from these detection totals.", '',
        '## Measured tuning', '',
        f"The same **{tuning['input_events']} actual saved 5145 events** were passed through Wazuh logtest: **{tuning['before_alerts']} before → {tuning['after_alerts']} after**. The broad rule counted **{tuning['successful_events']} successful authorised accesses** as false positives for the intended denial condition. Failure-only tuning retained **{tuning['denied_events']} of {tuning['denied_events']} denials**.", '',
        'This is a reproducible before/after replay, not a claim about two production observation periods. A temporary JSON-to-Windows group bridge checks Wazuh conditions after decoding; native EventChannel acceptance is established independently by the real agent alerts above. The temporary rule is removed and production XML restored after replay.', '',
        '[Engine results](../evidence/monitoring/engine-tuning.json) · [Before output](../evidence/monitoring/engine-before.txt) · [After output](../evidence/monitoring/engine-after.txt) · [Before rules](../evidence/monitoring/rules-before-tuning.xml)', '',
        '## Actual screenshots', '',
        '![Actual local Wazuh dashboard over the recorded ingestion window](../evidence/monitoring/dashboard-overview.png)', '',
        '![Actual local Wazuh filtered lockout alert](../evidence/monitoring/dashboard-lockout.png)', '',
        'The [final console test screenshot](../evidence/monitoring/console-final-test-failure.png) shows the fifth generic failure message. Lockout is established by AD state and event 4740, not by relabelling that screenshot as an explicit lockout message.', '',
        '## Honest limits', '',
        '- This is a small owned lab; no production SOC experience or adversary emulation is claimed.',
        '- Disabled sign-in, account lockout and denied share access do not establish successful T1078, T1110.001 or T1039 activity. No exploits, password search or denial of service were used.',
        '- Docker collection is a validated host-side export of existing stdout/stderr, not full Samba object auditing, CUPS job auditing or WireGuard per-peer telemetry. A Windows-reserved port prevented restarting Samba AD; the existing containers remained stopped for collection.',
        '- The Docker bridge has tightly bound ingress and a source allow-list; it does not claim network-level egress isolation. The collector and exercise targets are pinned in code.',
        '- The bundled Wazuh ATT&CK enrichment omitted T1098.007 on the captured group alerts. The dashboard explicitly derives its technique labels from the reviewed rule catalog; original alerts are preserved unchanged.',
        '- The low-memory stack is below normal production sizing. Agents and the manager ran in stages; source and ingestion timestamps differ. Both guests are saved outside lab sessions.', '']
    (ROOT / 'docs/monitoring-status.md').write_text('\n'.join(lines), encoding='utf-8')
    print('Seven evidence-backed SOC tickets and the coverage/metrics record rendered.')


if __name__ == '__main__': main()
