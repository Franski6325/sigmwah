# Sigmwah

Sigmwah converts [Sigma](https://github.com/SigmaHQ/sigma) detection rules into
[Wazuh](https://wazuh.com/) 4.x `analysisd` XML rulesets. It is a pySigma backend plus a
batch CLI. It does **not** use the deprecated `sigmac` toolchain.

**This is a community project. It is not affiliated with, endorsed by, or sponsored by
Wazuh Inc. or SigmaHQ.**

## Why it exists

Sigma moved from sigmac to [pySigma](https://github.com/SigmaHQ/pySigma). There was no
maintained Wazuh backend for current pySigma. Sigmwah fills that gap for Wazuh 4.x stable
(verified against `wazuh/wazuh-manager:4.14.7`).

## Requirements

- Python 3.11 or 3.12
- Optional: Docker, for `sigmwah validate --docker`

## Install

```bash
pip install -e ".[dev]"
```

## Convert rules

Sigmwah does **not** ship SigmaHQ rules. Download them yourself (Detection Rule License 1.1):

```bash
sigmwah download-sigmahq --version latest --dest ./sigmahq
sigmwah convert ./sigmahq --select product=windows -o rules_sigma.xml --report report.md
```

Useful flags:

```text
sigmwah convert PATH... -o rules_sigma.xml
  --target wazuh4|wazuh5          # default wazuh4
  --id-start 100100 --id-max 119999
  --select "product=windows"
  --tags attack.t1059
  --level medium+
  --exclude-tags test,tmp_check
  --format single|per-rule|per-group
  --mappings custom.yaml
  --dry-run --strict --fp-ignore
  --report report.md
```

Other commands:

```bash
sigmwah validate rules_sigma.xml
sigmwah validate rules_sigma.xml --docker --event '{"win":{"system":{"eventID":"1"}}}'
sigmwah ids --csv allocations.csv
```

Rule IDs are persisted in `.sigmwah_ids.json` so reconversion keeps the same Wazuh IDs.

## What converts, what does not

Converted:

- Field matches with `contains`, `contains|all`, `startswith`, `endswith`, `re`, wildcards, `base64`
- Windows EventChannel / Sysmon via `if_sid` / `if_group` (not `decoded_as json` on live events)
- Linux sshd/auth/auditd and web/proxy/firewall `program_name` entry conditions
- MITRE `attack.tXXXX` tags → `<mitre><id>TXXXX</id></mitre>`
- Sigma 2.0 `event_count` correlations → `frequency` / `timeframe` / `if_matched_sid`

Never converted silently:

- `value_count`, ordered/extended temporal correlation
- Numeric `lt/gt` modifiers, field-to-field equals
- Anything Wazuh cannot express — it is listed in the conversion report

`--target wazuh5` emits experimental Sigma YAML for the Wazuh 5 engine (WCS / no XML).
Wazuh 5.0 is beta; the quality gate remains Wazuh 4.x XML.

## Attribution

Every converted rule includes an XML comment with Sigma title, id, author, date, references,
and:

`Converted with Sigmwah from SigmaHQ (DRL 1.1)`

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Third-party: pySigma is LGPL-2.1-only. SigmaHQ rules (downloaded separately) are DRL 1.1.

## Documentation

- [Field and logsource mappings](docs/mappings.md)
- [Examples](docs/examples.md)
- [Load rules into Wazuh](docs/runbook.md)
