# Synthetic detection unit fixtures

These hand-authored records test the field conditions in `monitoring/local_rules.xml`.
They are **not Windows events, captured Wazuh alerts, tuning measurements or SOC evidence**.
The offline evaluator does not emulate EventChannel decoding, Wazuh precedence or correlation.
Actual saved events, alerts and Wazuh engine replay results belong under `evidence/monitoring/`.
