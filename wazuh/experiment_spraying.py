"""Temporary CI experiment: which correlation option counts distinct users?

For each candidate option, install a rule set containing only 100110 and a
spraying rule using that option, then check it against a 5-distinct-users
spray (should fire) and a 6-times-same-user burst (should not).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import time  # noqa: E402

from run_logtest import fired_rules, logtest, wait_ready  # noqa: E402

RULES = Path(__file__).parent / "rules" / "detection_rules.xml"
CANDIDATES = [
    "<different_srcuser />",
    "<different_dstuser />",
    "<different_user />",
    "<different_field>dstuser</different_field>",
]
SPRAY = [
    f"Sep 28 11:00:0{i} web1 sshd[811]: Failed password for {u} from 203.0.113.60 port {i} ssh2"
    for i, u in enumerate(["alice", "bob", "carol", "dave", "erin"])
]
SAME = [
    f"Sep 28 11:00:0{i} web1 sshd[811]: Failed password for root from 203.0.113.61 port {i} ssh2"
    for i in range(6)
]


def rules_with(option: str) -> str:
    text = RULES.read_text()
    base = re.search(r'  <rule id="100110".*?</rule>\n', text, re.S).group(0)
    spray = f"""  <rule id="100199" level="10" frequency="5" timeframe="600">
    <if_matched_sid>100110</if_matched_sid>
    <same_srcip />
    {option}
    <description>experiment</description>
  </rule>
"""
    return f'<group name="experiment,">\n{base}\n{spray}</group>\n'


TARGET = "/var/ossec/etc/rules/detection_rules.xml"


def install(text: str) -> None:
    Path("/tmp/exp_rules.xml").write_text(text)
    for cmd in (
        ["docker", "cp", "/tmp/exp_rules.xml", f"wazuh:{TARGET}"],
        ["docker", "exec", "wazuh", "chown", "root:wazuh", TARGET],
        ["docker", "exec", "wazuh", "/var/ossec/bin/wazuh-control", "restart"],
    ):
        subprocess.run(cmd, check=True, capture_output=True)
    wait_ready("wazuh", time.time() + 120)


def main() -> int:
    lines = []
    for option in CANDIDATES:
        try:
            install(rules_with(option))
            spray = set().union(*fired_rules(logtest("wazuh", SPRAY)))
            same = set().union(*fired_rules(logtest("wazuh", SAME)))
            lines.append(
                f"{option}: spray fires={'100199' in spray} (want True), "
                f"same-user fires={'100199' in same} (want False)"
            )
        except Exception as exc:  # noqa: BLE001 - report every candidate
            lines.append(f"{option}: error {exc}")
    report = "\n".join(lines)
    print(report)
    body = report.replace("%", "%25").replace("\n", "%0A")
    print(f"::notice title=spraying experiment::{body}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
