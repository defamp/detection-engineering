"""Generate the ATT&CK coverage table in README.md from the rule tags.

python -m detlab.coverage          # rewrite the table
python -m detlab.coverage --check  # exit 1 if README is out of date (CI)
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict

import yaml

from .rules import ROOT, rule_files

README = ROOT / "README.md"
START = "<!-- coverage:start -->"
END = "<!-- coverage:end -->"

# Names for the techniques used here; a test fails if a rule adds one without a name.
TECHNIQUE_NAMES = {
    "T1053.003": "Scheduled Task/Job: Cron",
    "T1098": "Account Manipulation",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1136.001": "Create Account: Local Account",
    "T1190": "Exploit Public-Facing Application",
    "T1505.003": "Server Software Component: Web Shell",
    "T1548.003": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
    "T1595.003": "Active Scanning: Wordlist Scanning",
}


def techniques() -> dict[str, list[tuple[str, str]]]:
    """technique ID -> [(rule title, rule path)]"""
    out: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for path in rule_files():
        rule = yaml.safe_load(path.read_text())
        for tag in rule.get("tags") or []:
            m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", tag)
            if m:
                out[m.group(1).upper()].append((rule["title"], str(path.relative_to(ROOT))))
    return dict(sorted(out.items()))


def _url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def render() -> str:
    rows = ["| Technique | Rules |", "|---|---|"]
    for tid, rules in techniques().items():
        name = TECHNIQUE_NAMES.get(tid, "")
        links = "<br>".join(f"[{title}]({path})" for title, path in rules)
        rows.append(f"| [{tid}]({_url(tid)}) {name} | {links} |")
    n_rules = len(rule_files())
    return (
        f"{START}\n{n_rules} rules covering {len(rows) - 2} techniques.\n\n"
        + "\n".join(rows)
        + f"\n{END}"
    )


def updated_readme(text: str) -> str:
    pattern = re.compile(re.escape(START) + ".*?" + re.escape(END), re.DOTALL)
    if not pattern.search(text):
        raise SystemExit(f"README.md is missing the {START} / {END} markers")
    return pattern.sub(lambda _: render(), text)


def main(argv: list[str]) -> int:
    current = README.read_text()
    new = updated_readme(current)
    if "--check" in argv:
        if new != current:
            print("README coverage table is out of date: run python -m detlab.coverage")
            return 1
        return 0
    README.write_text(new)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
