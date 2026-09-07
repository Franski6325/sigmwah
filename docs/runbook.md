# Runbook: loading Sigmwah rules into Wazuh 4.x

This is the operator path after `sigmwah convert`. It does not replace Wazuh’s own
documentation. Use a lab manager first.

## Install the XML

1. Convert rules on a workstation (Python 3.11+):

   ```bash
   sigmwah convert ./sigma-rules -o sigma_rules.xml --id-file .sigmwah_ids.json
   ```

2. Copy `sigma_rules.xml` to the manager:

   ```bash
   scp sigma_rules.xml root@wazuh-manager:/var/ossec/etc/rules/sigma_rules.xml
   ```

   Custom files under `/var/ossec/etc/rules/` are loaded after the built-in ruleset.
   Prefer a name that sorts last (for example `zzz_sigma_rules.xml`) if you chain
   `if_sid` across multiple custom files.

3. Fix ownership and restart analysisd:

   ```bash
   chown wazuh:wazuh /var/ossec/etc/rules/sigma_rules.xml
   chmod 640 /var/ossec/etc/rules/sigma_rules.xml
   systemctl restart wazuh-manager
   ```

4. Check `/var/ossec/logs/ossec.log` for `ERROR` / `WARNING` about rules. Duplicate
   IDs or invalid `if_sid` cause the rule to be skipped.

## ID range

Wazuh reserves 0–99999 for built-in rules. Sigmwah defaults to 100100–119999.
Keep `.sigmwah_ids.json` with the ruleset so reconversion does not reshuffle IDs.

## wazuh-logtest and EventChannel

`wazuh-logtest` does not simulate the `windows_eventchannel` decoder. Wazuh documents
a **temporary** patch to rule 60000 in `0575-win-base_rules.xml`:

- Remove `<category>ossec</category>`
- Change `<decoded_as>windows_eventchannel</decoded_as>` to `<decoded_as>json</decoded_as>`

Do this **only** inside a lab container. Sigmwah's validator applies that idea in
Docker and never patches the XML it emits.

Feed logtest a **synthetic** JSON event, for example:

```json
{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1","channel":"Microsoft-Windows-Sysmon/Operational","severityValue":"INFORMATION"},"eventdata":{"image":"C:\\Windows\\System32\\notepad.exe"}}}
```

Never replay malware artifacts.

```bash
sigmwah validate sigma_rules.xml --docker --event '<synthetic json>'
```

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Rule never fires on Windows agents | Used `decoded_as json` instead of `if_sid`/`if_group` |
| Rule fires in logtest but not live | Level-0 `if_sid` parent bug; switch mapping to `if_group` |
| `ossec.log` "invalid if_sid" | Parent ID not loaded yet; rename file to sort later |
| Duplicate ID | Overlapping `--id-start` with another custom ruleset |
| Too many rules from one Sigma file | OR across fields expands to DNF (one XML rule per branch) |

## Reload without full restart

`systemctl reload wazuh-manager` picks up rule file changes on many 4.x installs.
If rules do not appear, restart.
