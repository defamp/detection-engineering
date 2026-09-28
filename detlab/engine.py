"""Evaluate parsed Sigma rules against log events (dicts).

pySigma does the parsing: it turns the YAML detection section into a
condition tree with all value modifiers (contains, startswith, re, ...)
already applied. This module only walks that tree. Anything it does not
implement raises UnsupportedFeature, so a rule can never silently
"not match" because of a gap in the engine.

Matching semantics (documented, because backends differ):
- string comparisons are case-insensitive and must match the whole value;
  wildcards come from the rule (`contains` = *value*)
- `|re` uses re.search (unanchored); rules add ^/$ themselves when needed
- a missing field never matches, except against `null`
- a list-valued field matches if any element matches
- keywords (list items under a detection key) match if any string field
  value of the event contains them
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from typing import Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.correlations import (
    SigmaCorrelationConditionOperator,
    SigmaCorrelationRule,
    SigmaCorrelationType,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)


class UnsupportedFeature(Exception):
    """The rule uses a Sigma feature this engine does not implement."""


# ---------------------------------------------------------------- values


@lru_cache(maxsize=4096)
def _string_regex(parts: tuple, cased: bool) -> re.Pattern:
    out = []
    for part in parts:
        if part is SpecialChars.WILDCARD_MULTI:
            out.append(".*")
        elif part is SpecialChars.WILDCARD_SINGLE:
            out.append(".")
        elif isinstance(part, str):
            out.append(re.escape(part))
        else:
            raise UnsupportedFeature(f"string part {part!r}")
    return re.compile("".join(out), re.DOTALL | (0 if cased else re.IGNORECASE))


def _match_string(value: SigmaString, actual: Any) -> bool:
    if actual is None or isinstance(actual, (dict, list)):
        return False
    cased = type(value).__name__ == "SigmaCasedString"
    return _string_regex(tuple(value.s), cased).fullmatch(str(actual)) is not None


_RE_FLAGS = {
    SigmaRegularExpressionFlag.IGNORECASE: re.IGNORECASE,
    SigmaRegularExpressionFlag.MULTILINE: re.MULTILINE,
    SigmaRegularExpressionFlag.DOTALL: re.DOTALL,
}


def _match_value(value: Any, actual: Any) -> bool:
    if isinstance(actual, list):
        return any(_match_value(value, item) for item in actual)
    if isinstance(value, SigmaNull):
        return actual is None
    if actual is None:
        return False
    if isinstance(value, SigmaRegularExpression):
        flags = 0
        for flag in value.flags:
            flags |= _RE_FLAGS[flag]
        return re.search(value.regexp.to_plain(), str(actual), flags) is not None
    if isinstance(value, SigmaNumber):
        try:
            return float(actual) == float(value.number)
        except (TypeError, ValueError):
            return False
    if isinstance(value, SigmaBool):
        return actual is value.boolean or str(actual).lower() == str(value.boolean).lower()
    if isinstance(value, SigmaString):
        return _match_string(value, actual)
    raise UnsupportedFeature(f"value type {type(value).__name__}")


def _string_values(event: Any):
    if isinstance(event, dict):
        for v in event.values():
            yield from _string_values(v)
    elif isinstance(event, list):
        for v in event:
            yield from _string_values(v)
    elif event is not None:
        yield str(event)


def _eval(node: Any, event: dict) -> bool:
    if isinstance(node, ConditionAND):
        return all(_eval(arg, event) for arg in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval(arg, event) for arg in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _match_value(node.value, event.get(node.field))
    if isinstance(node, ConditionValueExpression):
        if not isinstance(node.value, SigmaString):
            raise UnsupportedFeature(f"keyword of type {type(node.value).__name__}")
        # A keyword matches anywhere in a value: wrap it as *keyword*
        wrapped = SigmaString("*") + node.value + SigmaString("*")
        return any(_match_string(wrapped, v) for v in _string_values(event))
    raise UnsupportedFeature(f"condition node {type(node).__name__}")


def rule_matches(rule: SigmaRule, event: dict) -> bool:
    """True if any of the rule's conditions matches the event."""
    return any(_eval(cond.parse(), event) for cond in rule.detection.parsed_condition)


# ----------------------------------------------------------- correlations


@dataclass(frozen=True)
class CorrelationAlert:
    group: tuple
    start: datetime
    end: datetime
    value: int


_OPS = {
    SigmaCorrelationConditionOperator.GT: lambda a, b: a > b,
    SigmaCorrelationConditionOperator.GTE: lambda a, b: a >= b,
    SigmaCorrelationConditionOperator.LT: lambda a, b: a < b,
    SigmaCorrelationConditionOperator.LTE: lambda a, b: a <= b,
    SigmaCorrelationConditionOperator.EQ: lambda a, b: a == b,
}


def _timestamp(event: dict) -> datetime:
    try:
        return datetime.fromisoformat(str(event["timestamp"]))
    except (KeyError, ValueError) as exc:
        raise ValueError(f"correlation events need an ISO 8601 'timestamp': {event}") from exc


def evaluate_correlation(rule: SigmaCorrelationRule, events: list[dict]) -> list[CorrelationAlert]:
    """Sliding-window evaluation of event_count / value_count correlations.

    Returns at most one alert per group: the first window in which the
    condition holds.
    """
    if rule.type not in (SigmaCorrelationType.EVENT_COUNT, SigmaCorrelationType.VALUE_COUNT):
        raise UnsupportedFeature(f"correlation type {rule.type.name}")
    cond = rule.condition
    if cond.op not in _OPS:
        raise UnsupportedFeature(f"correlation operator {cond.op.name}")
    base_rules = [ref.rule for ref in rule.rules]
    if any(not isinstance(r, SigmaRule) for r in base_rules):
        raise UnsupportedFeature("correlation over correlation rules")

    groups: dict[tuple, list[tuple[datetime, dict]]] = defaultdict(list)
    for event in events:
        if any(rule_matches(r, event) for r in base_rules):
            key = tuple(event.get(f) for f in rule.group_by or [])
            groups[key].append((_timestamp(event), event))

    span = rule.timespan.seconds
    alerts = []
    for key, hits in groups.items():
        hits.sort(key=lambda h: h[0])
        start = 0
        for end in range(len(hits)):
            while (hits[end][0] - hits[start][0]).total_seconds() > span:
                start += 1
            window = hits[start : end + 1]
            if rule.type is SigmaCorrelationType.EVENT_COUNT:
                value = len(window)
            else:
                value = len({e.get(cond.fieldref) for _, e in window} - {None})
            if _OPS[cond.op](value, cond.count):
                alerts.append(CorrelationAlert(key, window[0][0], window[-1][0], value))
                break
    return alerts
