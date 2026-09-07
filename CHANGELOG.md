# Changelog

All notable changes to Sigmwah are documented in this file.

## 0.1.0 — 2026-09-07

### Added

- Initial public release.
- `WazuhBackend` pySigma backend emitting Wazuh 4.x XML IR.
- Processing pipeline and YAML mappings for Windows EventChannel/Sysmon, Linux
  sshd/auth/auditd, and web/proxy/firewall log sources.
- CLI: `convert`, `download-sigmahq`, `validate`, `ids`.
- Persistent ID allocator (default 100100–119999) in `.sigmwah_ids.json`.
- Sigma 2.0 `event_count` correlation support; other correlation types reported as skipped.
- Experimental `--target wazuh5` YAML emitter.
- Golden tests, pySigma API contract tests, GitHub Actions on Python 3.11/3.12.
