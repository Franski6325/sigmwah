# TODO

Core conversion for Wazuh 4.x is implemented. Remaining work is optional hardening,
not placeholders for unfinished modules.

- Empirically re-check `if_sid` vs `if_group` on each new Wazuh 4.x patch release
  (regression: level-0 parent `if_sid` on live EventChannel, issue wazuh/wazuh#36029).
- Expand Wazuh 5 WCS field coverage when 5.x leaves beta.
- Optional pySigma plugin-directory listing once a public repository URL exists.
- Broader firewall/proxy decoder field tables from additional Wazuh decoder files.
- Wire `wazuh-logtest` EventChannel JSON patch into a documented compose file for
  local labs (already described in docs/runbook.md).
