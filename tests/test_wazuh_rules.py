"""Static checks for the Wazuh rule files (the behaviour is tested in CI with wazuh-logtest)."""

import re
from pathlib import Path

WAZUH = Path(__file__).resolve().parent.parent / "wazuh"


def _without_comments(text: str) -> str:
    return re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)


def test_no_xml_entities_in_patterns():
    # Wazuh's XML reader does not decode entities: "&amp;" in a regex is
    # matched literally. Use \x26 (or avoid &) instead.
    for path in WAZUH.rglob("*.xml"):
        body = _without_comments(path.read_text())
        for pattern in re.findall(r"<(?:regex|match)[^>]*>(.*?)</(?:regex|match)>", body, re.S):
            assert "&amp;" not in pattern and "&lt;" not in pattern, f"{path.name}: {pattern}"


def test_comments_are_valid_xml():
    # "--" is not allowed inside an XML comment
    for path in WAZUH.rglob("*.xml"):
        for comment in re.findall(r"<!--(.*?)-->", path.read_text(), re.S):
            assert "--" not in comment, f"{path.name}: '--' inside a comment"


def test_rule_ids_unique_and_in_custom_range():
    ids = re.findall(r'<rule id="(\d+)"', (WAZUH / "rules" / "detection_rules.xml").read_text())
    assert len(ids) == len(set(ids))
    assert all(100000 <= int(i) <= 120000 for i in ids)
