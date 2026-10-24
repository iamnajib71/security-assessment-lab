# Defender evidence register

Only captured Windows events, actual Wazuh alerts, real screenshots and measured
test results may be published here. Synthetic field cases live exclusively in
`tests/fixtures/soc/` and are never counted as live coverage.

Current status and per-rule acceptance are recorded in
[`docs/monitoring-status.md`](../../docs/monitoring-status.md).
Collection begins in ignored `private/monitoring/`; review for credentials,
keys and unrelated identities before copying selected records here. A manifest
contains SHA-256 hashes of published records and screenshots. Source Windows
event time/record ID and Wazuh ingestion time/alert ID are retained separately,
including when guests were saved and resumed to reduce host memory pressure.

Public Sysmon samples redact temporary PowerShell Direct transport tokens from
parent command lines. Original private captures are retained. Event identity,
timestamps and detection fields are unchanged; these remain real captured events.

The historical assessment evidence in the other folders is independent and
must never be rewritten to make defender results look complete.
