"""Rule hygiene: the things reviewers check by hand, enforced in CI."""

from __future__ import annotations

import re
import uuid
from pathlib import Path

import pytest
import yaml

from detlab.rules import RULES_DIR, rule_files

LEVELS = {"informational", "low", "medium", "high", "critical"}
TECHNIQUE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
TACTICS = {
    "attack.reconnaissance", "attack.resource-development", "attack.initial-access",
    "attack.execution", "attack.persistence", "attack.privilege-escalation",
    "attack.defense-evasion", "attack.credential-access", "attack.discovery",
    "attack.lateral-movement", "attack.collection", "attack.command-and-control",
    "attack.exfiltration", "attack.impact",
}  # fmt: skip


def _raw(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


@pytest.mark.parametrize("path", rule_files(), ids=lambda p: str(p.relative_to(RULES_DIR)))
def test_required_metadata(path):
    rule = _raw(path)
    for key in (
        "title",
        "id",
        "status",
        "description",
        "author",
        "date",
        "level",
        "falsepositives",
    ):
        assert rule.get(key), f"missing {key}"
    assert rule["level"] in LEVELS
    assert str(uuid.UUID(rule["id"])) == rule["id"]
    tags = rule.get("tags") or []
    assert any(TECHNIQUE.match(t) for t in tags), "needs an ATT&CK technique tag"
    assert any(t in TACTICS for t in tags), "needs an ATT&CK tactic tag"
    assert ("correlation" in rule) != ("detection" in rule)


def test_ids_and_names_are_unique():
    rules = [_raw(p) for p in rule_files()]
    ids = [r["id"] for r in rules]
    names = [r["name"] for r in rules if "name" in r]
    assert len(ids) == len(set(ids))
    assert len(names) == len(set(names))


def test_file_names_are_snake_case():
    for path in rule_files():
        assert re.fullmatch(r"[a-z0-9_]+\.yml", path.name), path
