import pytest

from detlab.parsers import parse_line
from detlab.scan import scan


def test_journalctl_short_iso():
    e = parse_line(
        "2026-09-27T20:23:02+07:00 kali-host sudo[4964]:   analyst : TTY=pts/0 ; "
        "PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/su"
    )
    assert e["timestamp"] == "2026-09-27T20:23:02+07:00"
    assert (e["host"], e["program"], e["pid"]) == ("kali-host", "sudo", 4964)
    assert e["message"].endswith("COMMAND=/usr/bin/su")


def test_classic_syslog_with_sshd_fields():
    e = parse_line(
        "Sep 28 10:00:05 web1 sshd[811]: Failed password for invalid user admin "
        "from 203.0.113.7 port 51234 ssh2",
        year=2026,
    )
    assert e["timestamp"] == "2026-09-28T10:00:05"
    assert e["message"].startswith("Failed password for ")
    assert (e["user"], e["src_ip"]) == ("admin", "203.0.113.7")


def test_program_without_pid():
    e = parse_line("2026-09-28T10:00:00+00:00 h CRON: (root) CMD (true)")
    assert e["program"] == "CRON"
    assert "pid" not in e


def test_combined_access_log():
    e = parse_line(
        '203.0.113.9 - - [28/Sep/2026:10:00:00 +0000] "GET /item.php?id=1%27%20OR%201%3D1 '
        'HTTP/1.1" 200 512 "-" "sqlmap/1.8"'
    )
    assert e["cs-uri-stem"] == "/item.php"
    assert e["cs-uri-query"] == "id=1%27%20OR%201%3D1"
    assert e["sc-status"] == 200
    assert e["cs-user-agent"] == "sqlmap/1.8"
    assert e["timestamp"] == "2026-09-28T10:00:00+00:00"


def test_unknown_format_raises():
    with pytest.raises(ValueError):
        parse_line("not a log line")


def test_scan_reports_rules_and_correlations():
    lines = [
        f"2026-09-28T10:00:0{i}+00:00 web1 sshd[1]: Failed password for root "
        f"from 203.0.113.7 port 5000{i} ssh2\n"
        for i in range(6)
    ]
    lines += [
        "-- Boot 7aa7df00094b4cc6b353d679a41b64e8 --\n",
        "2026-09-28T10:01:00+00:00 web1 sudo[2]:   bob : TTY=pts/0 ; PWD=/ ; USER=root ; "
        "COMMAND=/bin/bash\n",
        "garbage\n",
    ]
    alerts, skipped = scan(lines)
    assert skipped == 1
    assert any("SSH Brute Force" in a and "203.0.113.7" in a for a in alerts)
    assert any("Interactive Root Shell" in a for a in alerts)
    # informational building-block rules are not reported one event at a time
    assert not any("SSH Failed Password:" in a for a in alerts)
