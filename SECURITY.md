# Security policy

Sigmwah is a **local converter**. It does not run detections, does not talk to your Wazuh API unless you invoke `validate --docker`, and does not ship SigmaHQ rule content.

## What to report

Please report privately if you find:

- Path traversal or unexpected file writes outside the output path you passed
- XML / command injection in generated rules or in the docker validator
- Secrets leaked into reports, IDs files, or logs
- Dependency issues in the published package

Do **not** open a public issue with a working exploit.

Email the maintainer listed on the GitHub profile, or open a private advisory:

https://github.com/Franski6325/sigmwah/security/advisories/new

## What Sigmwah will not do

- Execute converted rules against live production without an explicit `--docker` validation you start
- Replay real malware artifacts (tests use synthetic events only)
- Relicense SigmaHQ rules (DRL 1.1 stays with the downloaded tree)
