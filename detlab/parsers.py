"""Turn raw log lines into the event dicts the rules are written against.

Supported formats:
- syslog with an ISO timestamp, as printed by `journalctl -o short-iso`
  2026-09-28T08:27:13+07:00 host sudo[4620]:   bob : TTY=pts/0 ; ... COMMAND=/usr/bin/su
- classic syslog (/var/log/auth.log), year taken from `year`
  Sep 28 08:27:13 host sshd[811]: Failed password for root from 203.0.113.7 port 22 ssh2
- Apache/Nginx combined access log
  203.0.113.9 - - [28/Sep/2026:10:00:00 +0000] "GET /a.php?id=1 HTTP/1.1" 200 512 "-" "curl/8"

sshd messages also get `user` and `src_ip` extracted, as a SIEM decoder would.
"""

from __future__ import annotations

import re
from datetime import datetime

_PROGRAM = r"(?P<host>\S+)\s+(?P<program>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)"
_SYSLOG_ISO = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+)\s+" + _PROGRAM + "$")
_SYSLOG_BSD = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})\s+" + _PROGRAM + "$")
_ACCESS = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<uri>\S+)(?: [^"]*)?" '
    r'(?P<status>\d{3}) \S+(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)
_SSHD_AUTH = re.compile(
    r"^(?:Failed|Accepted) \S+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port"
)
_SSHD_INVALID = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)")


def _syslog_event(m: re.Match, timestamp: str) -> dict:
    event = {
        "timestamp": timestamp,
        "host": m["host"],
        "program": m["program"],
        "message": m["message"],
    }
    if m["pid"]:
        event["pid"] = int(m["pid"])
    if m["program"] == "sshd":
        auth = _SSHD_AUTH.match(m["message"]) or _SSHD_INVALID.match(m["message"])
        if auth:
            event["user"] = auth["user"]
            event["src_ip"] = auth["ip"]
    return event


def parse_line(line: str, *, year: int | None = None) -> dict:
    """Parse one raw log line. Raises ValueError for unknown formats."""
    line = line.rstrip("\n")
    if m := _SYSLOG_ISO.match(line):
        return _syslog_event(m, datetime.fromisoformat(m["ts"]).isoformat())
    if m := _SYSLOG_BSD.match(line):
        year = year or datetime.now().year
        ts = datetime.strptime(f"{year} {m['ts']}", "%Y %b %d %H:%M:%S")
        return _syslog_event(m, ts.isoformat())
    if m := _ACCESS.match(line):
        stem, _, query = m["uri"].partition("?")
        event = {
            "timestamp": datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").isoformat(),
            "c-ip": m["ip"],
            "cs-method": m["method"],
            "cs-uri-stem": stem,
            "cs-uri-query": query,
            "sc-status": int(m["status"]),
        }
        if m["ua"] is not None:
            event["cs-referer"] = m["referer"]
            event["cs-user-agent"] = m["ua"]
        return event
    raise ValueError(f"unrecognised log format: {line[:80]!r}")
