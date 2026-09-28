"""Test the Wazuh rules with wazuh-logtest inside a running manager container.

For every sample file in tests/samples/ that names a `wazuh_rule`, each
case's raw lines are fed to one wazuh-logtest session (so frequency rules
see the whole sequence). A case expecting match/alert passes only if that
rule fires on some line; a benign case fails if it fires on any line.

    python wazuh/run_logtest.py --container wazuh
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "tests" / "samples"
LOGTEST = "/var/ossec/bin/wazuh-logtest"
PHASE1 = "**Phase 1: Completed pre-decoding."
RULE_ID = re.compile(r"^\s*id: '(\d+)'", re.MULTILINE)
POSITIVE = {"match", "alert"}


def logtest(container: str, lines: list[str], timeout: int = 120) -> str:
    proc = subprocess.run(
        ["docker", "exec", "-i", container, LOGTEST],
        input="\n".join(lines) + "\n",
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return proc.stdout + proc.stderr


def fired_rules(output: str) -> list[set[str]]:
    """Rule IDs that fired, one set per processed log line."""
    blocks = output.split(PHASE1)[1:]
    out = []
    for block in blocks:
        rules_part = block.split("**Phase 3", 1)
        out.append(set(RULE_ID.findall(rules_part[1])) if len(rules_part) == 2 else set())
    return out


def wait_ready(container: str, deadline: float) -> None:
    probe = "Sep 28 10:00:00 web1 sshd[1]: Accepted password for probe from 192.0.2.1 port 1 ssh2"
    last = ""
    while time.time() < deadline:
        try:
            last = logtest(container, [probe], timeout=30)
            if PHASE1 in last:
                return
        except subprocess.TimeoutExpired:
            last = "timeout"
        time.sleep(5)
    raise SystemExit(f"wazuh-logtest never became ready. Last output:\n{last}")


def annotate(title: str, text: str) -> None:
    # GitHub annotation; %0A keeps newlines so the log is readable in the API/UI
    body = text.replace("%", "%25").replace("\r", "").replace("\n", "%0A")
    print(f"::error title={title}::{body}")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--container", default="wazuh")
    p.add_argument("--ready-timeout", type=int, default=300)
    args = p.parse_args()

    wait_ready(args.container, time.time() + args.ready_timeout)

    total = failed = 0
    for path in sorted(SAMPLES.rglob("*.yml")):
        data = yaml.safe_load(path.read_text()) or {}
        if "wazuh_rule" not in data:
            continue
        expected = str(data["wazuh_rule"])
        rel = path.relative_to(SAMPLES)
        for i, case in enumerate(data["cases"]):
            total += 1
            raw = case["raw"]
            lines = [raw] if isinstance(raw, str) else list(raw)
            output = logtest(args.container, lines)
            per_line = fired_rules(output)
            fired = set().union(*per_line) if per_line else set()
            want = case["expect"] in POSITIVE
            ok = len(per_line) == len(lines) and (expected in fired) == want
            status = "ok  " if ok else "FAIL"
            label = f"{rel}::{i} {case['description']}"
            print(f"{status} {label} (rule {expected}, fired {sorted(fired)})")
            if not ok:
                failed += 1
                why = (
                    f"logtest processed {len(per_line)} of {len(lines)} lines"
                    if len(per_line) != len(lines)
                    else f"expected rule {expected} to {'fire' if want else 'NOT fire'}"
                )
                annotate(label, f"{why}\n\n{output}")
    print(f"\n{total - failed}/{total} passed")
    if total == 0:
        print("no sample files with wazuh_rule found")
        return 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
