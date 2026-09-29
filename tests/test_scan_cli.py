"""CLI entry point of detlab.scan (file, stdin, exit codes, --year)."""

import io

from detlab.scan import main

BURST = "".join(
    f"Sep 28 10:00:0{i} web1 sshd[1]: Failed password for root from 2001:db8::7 port 5000{i} ssh2\n"
    for i in range(6)
)


def test_main_reads_file_and_reports(tmp_path, capsys):
    log = tmp_path / "auth.log"
    log.write_text(BURST + "garbage line\n")
    assert main([str(log), "--year", "2026"]) == 1
    out, err = capsys.readouterr()
    assert "SSH Brute Force From Single Source" in out
    assert "2001:db8::7" in out and "2026-09-28" in out
    assert "1 line(s) in unknown formats skipped" in err


def test_main_reads_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(BURST))
    assert main(["-"]) == 1
    assert "SSH Brute Force" in capsys.readouterr().out


def test_main_quiet_input_exits_zero(tmp_path, capsys):
    log = tmp_path / "auth.log"
    log.write_text(
        "Sep 28 10:00:00 web1 sshd[1]: Accepted password for alice from 198.51.100.4 port 1 ssh2\n"
    )
    assert main([str(log)]) == 0
    _, err = capsys.readouterr()
    assert "0 alert(s); 0 line(s) in unknown formats skipped" in err
