"""Every rule must catch its attack samples and ignore its benign samples."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from sigma.correlations import SigmaCorrelationRule

from detlab.engine import evaluate_correlation, rule_matches
from detlab.parsers import parse_line
from detlab.rules import RULES_DIR, rule_by_file, sample_file

RULES = rule_by_file()


def _case_id(val):
    return str(Path(val).relative_to(RULES_DIR)) if isinstance(val, Path) else None


def _load_cases(rule_path: Path) -> list[dict]:
    path = sample_file(rule_path)
    assert path.exists(), f"missing samples file {path}"
    data = yaml.safe_load(path.read_text()) or {}
    cases = data.get("cases") or []
    assert cases, f"{path}: no cases"
    return cases


def _is_correlation(rule) -> bool:
    return isinstance(rule, SigmaCorrelationRule)


@pytest.mark.parametrize("rule_path", sorted(RULES), ids=_case_id)
def test_rule_has_positive_and_negative_samples(rule_path):
    cases = _load_cases(rule_path)
    positive = {"alert"} if _is_correlation(RULES[rule_path]) else {"match"}
    negative = {"no_alert"} if _is_correlation(RULES[rule_path]) else {"no_match"}
    expects = [c.get("expect") for c in cases]
    assert set(expects) <= positive | negative, f"invalid expect values: {expects}"
    assert positive & set(expects), "needs at least one case that should fire"
    assert negative & set(expects), "needs at least one benign case that must not fire"


def _all_cases():
    for rule_path in sorted(RULES):
        for i, case in enumerate(_load_cases(rule_path)):
            label = f"{rule_path.relative_to(RULES_DIR)}::{i}:{case.get('description', '')}"
            yield pytest.param(rule_path, case, id=label)


@pytest.mark.parametrize(("rule_path", "case"), list(_all_cases()))
def test_sample(rule_path, case):
    rule = RULES[rule_path]
    if _is_correlation(rule):
        assert ("events" in case) != ("raw" in case), "correlation cases need events or raw"
        events = case.get("events") or [parse_line(line) for line in case["raw"]]
        alerts = evaluate_correlation(rule, events)
        if case["expect"] == "alert":
            assert alerts, "expected an alert"
            if "groups" in case:
                assert sorted(a.group for a in alerts) == sorted(tuple(g) for g in case["groups"])
        else:
            assert not alerts, f"unexpected alert(s): {alerts}"
    else:
        assert ("event" in case) != ("raw" in case), "rule cases need an event or a raw line"
        event = case.get("event") or parse_line(case["raw"])
        assert rule_matches(rule, event) == (case["expect"] == "match")


def test_wazuh_samples_are_raw_lines():
    """Cases tested in Wazuh must be raw lines: wazuh-logtest decodes them itself."""
    for rule_path in sorted(RULES):
        data = yaml.safe_load(sample_file(rule_path).read_text()) or {}
        if "wazuh_rule" in data:
            rules = data["wazuh_rule"]
            assert all(isinstance(r, int) for r in (rules if isinstance(rules, list) else [rules]))
            for case in data["cases"]:
                assert "raw" in case, f"{rule_path}: {case.get('description')} has no raw line"
                if "wazuh_skip" in case:
                    # a skip must say why, and must not hide a case that should fire
                    assert len(str(case["wazuh_skip"])) > 20, "explain the skip"
                    assert case["expect"] in ("no_match", "no_alert"), "only benign cases may skip"
                if "wazuh_gap" in case:
                    assert len(str(case["wazuh_gap"])) > 20, "explain the gap"
                    assert case["expect"] in ("match", "alert"), "a gap is a missed detection"
