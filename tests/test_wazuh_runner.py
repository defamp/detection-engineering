"""The logtest output parser, checked against real wazuh-logtest 4.9.2 output."""

import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "run_logtest", Path(__file__).resolve().parent.parent / "wazuh" / "run_logtest.py"
)
run_logtest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run_logtest)

# Trimmed from a CI run: one line that reached rule 5760, one that only decoded.
OUTPUT = """
Starting wazuh-logtest v4.9.2
Type one log per line

**Phase 1: Completed pre-decoding.
\tfull event: 'Sep 28 10:00:00 web1 sshd[811]: Failed password for root from 203.0.113.7'
\ttimestamp: 'Sep 28 10:00:00'

**Phase 2: Completed decoding.
\tname: 'sshd'
\tsrcip: '203.0.113.7'

**Phase 3: Completed filtering (rules).
\tid: '5760'
\tlevel: '5'
\tdescription: 'sshd: authentication failed.'
**Alert to be generated.

**Phase 1: Completed pre-decoding.
\tfull event: 'hello'

**Phase 2: Completed decoding.
\tNo decoder matched
"""


def test_fired_rules_per_line():
    assert run_logtest.fired_rules(OUTPUT) == [{"5760"}, set()]


def test_decoder_fields_named_id_are_not_rule_ids():
    out = OUTPUT.replace("\tsrcip: '203.0.113.7'", "\tsrcip: '203.0.113.7'\n\tid: '4242'")
    assert run_logtest.fired_rules(out) == [{"5760"}, set()]
