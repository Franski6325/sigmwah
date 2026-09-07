"""XML well-formedness checks and optional wazuh-logtest Docker smoke tests."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from sigmwah.exceptions import ValidationError

DEFAULT_IMAGE = "wazuh/wazuh-manager:4.14.7"
LOGTEST_PATCH_SNIPPET = """
<!-- Sigmwah wazuh-logtest patch: EventChannel is not simulated by logtest.
     Production rules keep if_sid/if_group. This patch is applied only inside
     the validation container, never to emitted rulesets. -->
"""


@dataclass
class ValidationResult:
    well_formed: bool
    messages: list[str] = field(default_factory=list)
    docker_ran: bool = False
    logtest_hits: list[str] = field(default_factory=list)


def validate_xml(path: Path) -> ValidationResult:
    result = ValidationResult(well_formed=True)
    text = path.read_text(encoding="utf-8")
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        groups = [root] if root.tag == "group" else list(root)
    except ET.ParseError:
        wrapped = f"<sigmwah>{_strip_decl(text)}</sigmwah>"
        try:
            forest = ET.fromstring(wrapped)
        except ET.ParseError as exc:
            result.well_formed = False
            result.messages.append(f"XML is not well-formed: {exc}")
            return result
        groups = [child for child in list(forest) if child.tag == "group"]
        if not groups:
            result.well_formed = False
            result.messages.append("XML is not well-formed: junk after document element")
            return result
    ids: set[str] = set()
    for group in groups:
        if group.tag != "group":
            result.messages.append(f"Unexpected top-level tag <{group.tag}>")
            continue
        name = group.attrib.get("name", "")
        if name and not name.endswith(","):
            result.messages.append(
                f"Group name {name!r} should end with a comma (Wazuh convention)"
            )
        for rule in group.findall("rule"):
            rule_id = rule.attrib.get("id")
            if not rule_id:
                result.messages.append("Rule is missing id")
                continue
            if rule_id in ids:
                result.messages.append(f"Duplicate rule id {rule_id}")
            ids.add(rule_id)
            if "level" not in rule.attrib:
                result.messages.append(f"Rule {rule_id} is missing level")
            if rule.find("description") is None:
                result.messages.append(f"Rule {rule_id} is missing description")
    if not ids:
        result.messages.append("No <rule> elements found")
    return result


def smoke_test_docker(
    rules_path: Path,
    events: list[str],
    image: str = DEFAULT_IMAGE,
    timeout: int = 180,
) -> ValidationResult:
    """Mount the ruleset in wazuh-manager and run wazuh-logtest on synthetic events."""
    result = validate_xml(rules_path)
    if not result.well_formed:
        return result
    if shutil.which("docker") is None:
        result.messages.append("Docker is not available; skipped wazuh-logtest smoke test")
        return result
    result.docker_ran = True
    name = f"sigmwah-logtest-{int(time.time())}"
    with tempfile.TemporaryDirectory(prefix="sigmwah-val-") as tmp:
        tmp_path = Path(tmp)
        shutil.copy2(rules_path, tmp_path / "sigma_rules.xml")
        try:
            subprocess.run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    name,
                    "-v",
                    f"{tmp_path / 'sigma_rules.xml'}:/var/ossec/etc/rules/sigma_rules.xml:ro",
                    image,
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
            result.messages.append(f"Failed to start {image}: {exc}")
            _docker_rm(name)
            return result
        try:
            _wait_for_manager(name, timeout=timeout)
            ossec_log = _docker_exec(
                name, ["bash", "-lc", "tail -n 80 /var/ossec/logs/ossec.log || true"]
            )
            if "ERROR" in ossec_log.upper() and "rules" in ossec_log.lower():
                result.messages.append("ossec.log contains rule-related errors:\n" + ossec_log)
            for event in events:
                output = _docker_exec(
                    name,
                    ["bash", "-lc", f"/var/ossec/bin/wazuh-logtest <<'EOF'\n{event}\nEOF"],
                )
                result.logtest_hits.append(output)
                if "**Phase 3: Completed filtering" not in output and "Phase 3" not in output:
                    result.messages.append(
                        "wazuh-logtest did not complete phase 3 for a synthetic event"
                    )
        finally:
            _docker_rm(name)
    return result


def _strip_decl(text: str) -> str:
    if text.startswith("<?xml"):
        end = text.find("?>")
        if end != -1:
            return text[end + 2 :]
    return text


def _wait_for_manager(name: str, timeout: int) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        logs = _docker_exec(
            name,
            [
                "bash",
                "-lc",
                "test -x /var/ossec/bin/wazuh-logtest && echo READY || echo WAIT",
            ],
        )
        if "READY" in logs:
            return
        time.sleep(3)
    raise ValidationError(f"Timed out waiting for wazuh-manager container {name}")


def _docker_exec(name: str, command: list[str]) -> str:
    completed = subprocess.run(
        ["docker", "exec", name, *command],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return (completed.stdout or "") + (completed.stderr or "")


def _docker_rm(name: str) -> None:
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True, timeout=30)
