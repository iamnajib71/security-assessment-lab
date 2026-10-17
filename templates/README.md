# Reviewed community template subset

Source: projectdiscovery/nuclei-templates at
`17f5725dc10ced09f464dd2d255c19957aad51e7` (MIT licensed).

Only the four adjacent YAML files run. Review their HTTP GET paths before use.
No credentials, fuzzing, exploits, callbacks, workflows or redirects. The scanner
disables template updates and OAST and applies an IP egress firewall. Retrieval
of tools/templates is setup traffic, never an internet assessment.

Nuclei was selected over Greenbone because a bounded, inspectable set of templates
is lightweight enough to repeat on this small Docker lab. This is an
unauthenticated community-template scan supplemented by authenticated service
checks, not a full CVE database audit. Panel detection is informational; a login
page is not proof of missing authentication. A negative result proves only that
these templates did not match. Versions are inventory, not unsupported CVE claims.
