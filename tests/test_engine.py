"""Pin down the matching semantics the rules rely on."""

from __future__ import annotations

import pytest
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule

from detlab.engine import UnsupportedFeature, evaluate_correlation, rule_matches

HEADER = """
title: t
id: 00000000-0000-4000-8000-000000000001
status: test
logsource: {product: test}
"""


def rule(detection: str) -> SigmaRule:
    return SigmaRule.from_yaml(HEADER + "detection:\n" + detection)


def test_plain_value_is_whole_value_and_case_insensitive():
    r = rule("  s: {program: sshd}\n  condition: s\n")
    assert rule_matches(r, {"program": "SSHD"})
    assert not rule_matches(r, {"program": "sshd2"})


def test_cased_modifier_is_case_sensitive():
    r = rule("  s: {program|cased: sshd}\n  condition: s\n")
    assert rule_matches(r, {"program": "sshd"})
    assert not rule_matches(r, {"program": "SSHD"})


def test_contains_startswith_endswith():
    r = rule(
        "  a: {m|contains: mid}\n  b: {m|startswith: pre}\n  c: {m|endswith: end}\n"
        "  condition: a and b and c\n"
    )
    assert rule_matches(r, {"m": "pre-mid-end"})
    assert not rule_matches(r, {"m": "x-pre-mid-end"})


def test_wildcards_and_escaped_wildcard():
    r = rule("  s: {m: 'a*c?e'}\n  condition: s\n")
    assert rule_matches(r, {"m": "abbbcde"})
    assert not rule_matches(r, {"m": "abbbce"})
    literal = rule("  s: {m: 'a\\*b'}\n  condition: s\n")
    assert rule_matches(literal, {"m": "a*b"})
    assert not rule_matches(literal, {"m": "axb"})


def test_regex_is_unanchored_search_with_flags():
    r = rule("  s: {m|re: 'b+c'}\n  condition: s\n")
    assert rule_matches(r, {"m": "abbbcd"})
    assert not rule_matches(r, {"m": "ABBC"})
    ri = rule("  s: {m|re|i: 'b+c'}\n  condition: s\n")
    assert rule_matches(ri, {"m": "ABBC"})


def test_missing_field_and_null():
    r = rule("  s: {user: alice}\n  condition: s\n")
    assert not rule_matches(r, {})
    n = rule("  s: {user: null}\n  condition: s\n")
    assert rule_matches(n, {})
    assert rule_matches(n, {"user": None})
    assert not rule_matches(n, {"user": "alice"})


def test_list_field_matches_any_element_and_list_value_is_or():
    r = rule("  s: {group: [sudo, wheel]}\n  condition: s\n")
    assert rule_matches(r, {"group": ["users", "wheel"]})
    assert not rule_matches(r, {"group": ["users"]})


def test_numbers():
    r = rule("  s: {status: 200}\n  condition: s\n")
    assert rule_matches(r, {"status": 200})
    assert rule_matches(r, {"status": "200"})
    assert not rule_matches(r, {"status": 404})


def test_keywords_search_all_values():
    r = rule("  kw: ['UNION SELECT']\n  condition: kw\n")
    assert rule_matches(r, {"a": 1, "b": {"c": "x union select y"}})
    assert not rule_matches(r, {"a": "union"})


def test_not_and_1_of():
    r = rule("  a: {x: 1}\n  b: {y: 1}\n  f: {z: 1}\n  condition: 1 of a or b and not f\n")
    assert rule_matches(r, {"x": 1, "z": 1})  # `and` binds tighter than `or`
    assert rule_matches(r, {"y": 1})
    assert not rule_matches(r, {"y": 1, "z": 1})


def test_unsupported_modifier_raises_instead_of_not_matching():
    r = rule("  s: {ip|cidr: 10.0.0.0/8}\n  condition: s\n")
    with pytest.raises(UnsupportedFeature):
        rule_matches(r, {"ip": "10.1.2.3"})


CORRELATION = """
title: base
id: 00000000-0000-4000-8000-000000000002
name: base
status: test
logsource: {product: test}
detection:
  s: {kind: fail}
  condition: s
---
title: corr
id: 00000000-0000-4000-8000-000000000003
status: test
correlation:
  type: %s
  rules: [base]
  group-by: [ip]
  timespan: 60s
  condition:
    %s
"""


def correlation(kind: str, condition: str):
    col = SigmaCollection.from_yaml(CORRELATION % (kind, condition))
    col.resolve_rule_references()
    return col.rules[1]


def ev(t: int, ip: str = "a", **kw) -> dict:
    return {
        "timestamp": f"2026-01-01T00:{t // 60:02d}:{t % 60:02d}",
        "kind": "fail",
        "ip": ip,
        **kw,
    }


def test_event_count_window_boundary_is_inclusive():
    c = correlation("event_count", "gte: 3")
    assert evaluate_correlation(c, [ev(0), ev(30), ev(60)])  # exactly 60s apart
    assert not evaluate_correlation(c, [ev(0), ev(30), ev(61)])


def test_event_count_ignores_non_matching_and_groups_separately():
    c = correlation("event_count", "gte: 2")
    events = [ev(0, "a"), ev(1, "b"), {**ev(2, "a"), "kind": "ok"}]
    assert not evaluate_correlation(c, events)
    alerts = evaluate_correlation(c, events + [ev(3, "b")])
    assert [a.group for a in alerts] == [("b",)]
    assert alerts[0].value == 2


def test_events_out_of_order_are_sorted():
    c = correlation("event_count", "gte: 3")
    assert evaluate_correlation(c, [ev(50), ev(0), ev(20)])


def test_value_count_counts_distinct_values():
    c = correlation("value_count", "field: user\n    gte: 2")
    assert not evaluate_correlation(c, [ev(0, user="x"), ev(1, user="x")])
    assert evaluate_correlation(c, [ev(0, user="x"), ev(1, user="y")])


def test_unsupported_correlation_type_raises():
    c = correlation("temporal", "gte: 1")
    with pytest.raises(UnsupportedFeature):
        evaluate_correlation(c, [ev(0)])


def test_correlation_events_need_timestamps():
    c = correlation("event_count", "gte: 1")
    with pytest.raises(ValueError, match="timestamp"):
        evaluate_correlation(c, [{"kind": "fail", "ip": "a"}])
