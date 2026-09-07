# Field and logsource mappings

Decoder field names in Wazuh XML **do not** use the `data.` prefix. Alert JSON
uses `data.win.system.eventID`; the matching rule field is `win.system.eventID`.

Verified against Wazuh **4.14.7** ruleset files from
`https://github.com/wazuh/wazuh/tree/v4.14.7/ruleset/rules`.

## Logsource entry conditions

### Windows EventChannel

Live EventChannel events are decoded as `windows_eventchannel`. Rule **60000** is
the tree root (`0575-win-base_rules.xml`). Custom rules that use
`<decoded_as>json</decoded_as>` do **not** fire on production EventChannel
(see wazuh/wazuh#13589). Sigmwah therefore emits `if_sid` / `if_group`.

| Sigma logsource | Wazuh entry | Evidence |
| --- | --- | --- |
| product=windows, service=security | `if_sid` 60001 (channel `^Security$`) | 0575-win-base_rules.xml |
| product=windows, service=system | `if_sid` 60002 | same |
| product=windows, service=application | `if_sid` 60003 | same |
| product=windows, service=sysmon | `if_sid` 60004 | same |
| product=windows (fallback) | `if_sid` 60000 | same |

Attach to the **channel** parent (60001, 60004, …), not only 60000. Wazuh walks a
single tree path; a sibling of 60001 never sees Security events that already took
the 60001 branch.

### Sysmon categories

Built-in Sysmon informational events hang off 61600 (`0595-win-sysmon_rules.xml`).
Wazuh's own detections use `<if_group>sysmon_event1</if_group>` rather than
`if_sid` 61603. Prefer `if_group` because live analysisd has regressed on
`if_sid` of level-0 EventChannel parents (wazuh/wazuh#36029).

| Sigma category | if_group | Event ID |
| --- | --- | --- |
| process_creation | sysmon_event1 | 1 |
| network_connection | sysmon_event3 | 3 |
| process_access | sysmon_event_10 | 10 |
| file_event | sysmon_event_11 | 11 |
| registry_set / registry_event | sysmon_event_13 | 13 |
| dns_query | sysmon_event_22 | 22 |
| (see windows.yaml for the rest) | | |

### Linux / web / firewall

| Sigma logsource | Wazuh entry | Evidence |
| --- | --- | --- |
| product=linux, service=sshd | `if_sid` 5700 (`decoded_as` sshd) | 0095-sshd_rules.xml |
| product=linux, service=auth / category=authentication | `if_sid` 5500 | pam/auth grouping |
| product=linux, service=auditd | `if_sid` 80700 | 0365-auditd_rules.xml |
| product=nginx / apache / squid | `program_name` PCRE2 | syslog-family decoders |
| category=firewall | `program_name` kernel/filterlog/firewalld | syslog |

## Windows field mapping (XML name → alert JSON)

| Sigma field | Wazuh XML field | Alert JSON |
| --- | --- | --- |
| EventID | win.system.eventID | data.win.system.eventID |
| Provider_Name | win.system.providerName | data.win.system.providerName |
| Channel | win.system.channel | data.win.system.channel |
| CommandLine | win.eventdata.commandLine | data.win.eventdata.commandLine |
| Image | win.eventdata.image | data.win.eventdata.image |
| ParentImage | win.eventdata.parentImage | data.win.eventdata.parentImage |
| TargetUserName | win.eventdata.targetUserName | data.win.eventdata.targetUserName |
| IpAddress | win.eventdata.ipAddress | data.win.eventdata.ipAddress |

The complete table lives in `src/sigmwah/mappings/windows.yaml`. Override or extend
with `--mappings custom.yaml`.

## Severity → Wazuh level

| Sigma | Wazuh level |
| --- | --- |
| informational | 3 |
| low | 4 |
| medium | 6 |
| high | 10 |
| critical | 12 |

Configurable in mapping YAML (`severity:`).

## Sigma modifiers → PCRE2

Default match element is `<field name="..." type="pcre2">` (Wazuh ≥ 4.2).
Keyword (fieldless) values use `<regex type="pcre2">`.

| Modifier | Pattern |
| --- | --- |
| (none, exact) | `^(?i)value$` |
| contains | unanchored / leading-trailing `.*` from pySigma |
| contains\|all | multiple `<field>` AND (Wazuh ANDs children) |
| startswith / endswith | `^` / `$` after wildcard conversion |
| re | PCRE2 as written |
| base64 | pySigma encodes the literal (wildcards rejected by pySigma) |
| CIDR | expanded IPv4 wildcard regex |

OR of different fields is expanded to DNF: one Wazuh `<rule>` per conjunction.
Same-field OR becomes a PCRE2 alternation.

## Correlation

| Sigma 2.0 | Wazuh 4.x | Action |
| --- | --- | --- |
| event_count | frequency + timeframe + if_matched_sid | Convert |
| group-by srcip/user | same_source_ip / same_user / same_field | Convert when mapped |
| value_count | — | Skip with report |
| temporal / ordered | — | Skip with report |

Wazuh 5.x has **no** native correlation in the Sigma-YAML rule format; `--target wazuh5`
skips correlation rules on purpose.
