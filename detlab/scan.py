"""Run every rule against a raw log file and print what fires.

journalctl -o short-iso _COMM=sshd _COMM=sudo --since today | python -m detlab.scan -
python -m detlab.scan /var/log/apache2/access.log
"""

from __future__ import annotations

import argparse
import sys

from sigma.correlations import SigmaCorrelationRule

from .engine import evaluate_correlation, rule_matches
from .parsers import parse_line
from .rules import load_collection


def scan(lines, *, year: int | None = None) -> tuple[list[str], int]:
    events, skipped = [], 0
    for line in lines:
        if not line.strip() or line.startswith("-- "):  # journalctl boot markers
            continue
        try:
            events.append(parse_line(line, year=year))
        except ValueError:
            skipped += 1
    out = []
    for rule in load_collection().rules:
        if isinstance(rule, SigmaCorrelationRule):
            for alert in evaluate_correlation(rule, events):
                out.append(
                    f"[{rule.level.name.lower()}] {rule.title}: group={alert.group} "
                    f"count={alert.value} {alert.start.isoformat()} .. {alert.end.isoformat()}"
                )
        elif rule.level is None or rule.level.name != "INFORMATIONAL":
            for event in events:
                if rule_matches(rule, event):
                    detail = event.get("message") or event.get("cs-uri-stem", "")
                    out.append(
                        f"[{rule.level.name.lower()}] {rule.title}: {event['timestamp']} {detail}"
                    )
    return out, skipped


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="detlab.scan", description=__doc__.splitlines()[0])
    p.add_argument("file", help="log file, or - for stdin")
    p.add_argument("--year", type=int, help="year for classic syslog lines without one")
    args = p.parse_args(argv)
    handle = sys.stdin if args.file == "-" else open(args.file, encoding="utf-8", errors="replace")
    with handle:
        alerts, skipped = scan(handle, year=args.year)
    for line in alerts:
        print(line)
    print(f"{len(alerts)} alert(s); {skipped} line(s) in unknown formats skipped", file=sys.stderr)
    return 1 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())
