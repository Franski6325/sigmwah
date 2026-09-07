# Examples

## Input (synthetic Sigma)

See `tests/golden/01_contains.yml` (original test rule, not copied from SigmaHQ):

```yaml
title: Synthetic PowerShell Image
id: 11111111-1111-4111-8111-111111111111
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|contains: powershell
  condition: selection
level: medium
tags:
  - attack.t1059.001
```

## Output (Wazuh 4.x XML, abbreviated)

```xml
<group name="sigma,windows,sysmon,">
  <rule id="100100" level="6">
    <!-- Sigma title: Synthetic PowerShell Image | ... | Converted with Sigmwah from SigmaHQ (DRL 1.1) -->
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i).*powershell.*</field>
    <options>no_full_log</options>
    <description>Synthetic PowerShell Image</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
    <group>sigma,windows,sysmon,</group>
  </rule>
</group>
```

Exact golden XML is versioned under `tests/golden/*.xml` after the first test run.

## User mapping overlay

```yaml
fields:
  MyCorpField: win.eventdata.commandLine
logsources:
  - id: windows-my-channel
    product: windows
    service: mychannel
    groups: [sigma, windows]
    entry:
      if_sid: "60000"
      fields:
        win.system.channel: "^My/Channel$"
severity:
  medium: 7
```

```bash
sigmwah convert rules/ --mappings overlay.yaml -o /var/ossec/etc/rules/sigma_rules.xml
```
