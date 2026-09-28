# Detection Engineering

> Sigma detection rules for Linux and web-server attacks, mapped to MITRE ATT&CK and
> **tested in CI**: every rule has attack samples it must catch and benign samples it
> must ignore.

[![ci](https://github.com/defamp/detection-engineering/actions/workflows/ci.yml/badge.svg)](https://github.com/defamp/detection-engineering/actions/workflows/ci.yml)
[![wazuh](https://github.com/defamp/detection-engineering/actions/workflows/wazuh.yml/badge.svg)](https://github.com/defamp/detection-engineering/actions/workflows/wazuh.yml)

## Why "as code"

Detection rules are code that runs in production. Without tests, a rule can
stop firing after an edit, or fire on every admin login, and nobody notices
until an incident is missed or analysts drown in noise. This repo treats
rules like software:

- **Rules** are written in [Sigma](https://sigmahq.io), the vendor-neutral
  format that converts to Splunk, Elastic, Wazuh and other SIEM queries.
- **Samples** next to each rule define what it must detect (`match` /
  `alert`) and what it must not (`no_match` / `no_alert`), including known
  evasions and false-positive traps.
- **CI** validates every rule with `sigma check`, runs every sample through a
  test engine, checks metadata (ATT&CK tags, level, false positives) and keeps
  the coverage table below in sync.

## ATT&CK coverage

<!-- coverage:start -->
11 rules covering 9 techniques.

| Technique | Rules |
|---|---|
| [T1053.003](https://attack.mitre.org/techniques/T1053/003/) Scheduled Task/Job: Cron | [User Crontab Modified](rules/linux/crontab_modified.yml) |
| [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation | [User Added To Privileged Group](rules/linux/user_added_to_privileged_group.yml) |
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Brute Force: Password Guessing | [SSH Brute Force From Single Source](rules/linux/ssh_bruteforce.yml)<br>[SSH Failed Password](rules/linux/ssh_failed_password.yml) |
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Brute Force: Password Spraying | [SSH Password Spraying From Single Source](rules/linux/ssh_password_spraying.yml) |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) Create Account: Local Account | [New Local User Account Created](rules/linux/new_local_user.yml) |
| [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application | [Path Traversal Attempt](rules/web/path_traversal.yml)<br>[SQL Injection Attempt In Query String](rules/web/sql_injection.yml) |
| [T1505.003](https://attack.mitre.org/techniques/T1505/003/) Server Software Component: Web Shell | [Web Shell Command Execution Parameter](rules/web/webshell_command_param.yml) |
| [T1548.003](https://attack.mitre.org/techniques/T1548/003/) Abuse Elevation Control Mechanism: Sudo and Sudo Caching | [Interactive Root Shell Via Sudo](rules/linux/sudo_root_shell.yml) |
| [T1595.003](https://attack.mitre.org/techniques/T1595/003/) Active Scanning: Wordlist Scanning | [Probe For Sensitive Files](rules/web/sensitive_file_probe.yml) |
<!-- coverage:end -->

## Layout

```
rules/                    Sigma rules, one per file
  linux/                  auth.log / cron (sshd, sudo, useradd, usermod, crontab)
  web/                    web access logs
tests/samples/            test cases, same path as the rule they test
detlab/engine.py          evaluates parsed Sigma rules and correlations on events
detlab/parsers.py         raw syslog / journalctl / access-log lines -> events
detlab/scan.py            run all rules against a log file
tests/                    sample, engine and metadata tests
wazuh/rules, wazuh/decoders   Wazuh rules and decoder for the same detections
wazuh/run_logtest.py      runs the samples through wazuh-logtest (CI job "wazuh")
```

## Event fields

Samples are already-parsed events, the way a SIEM stores them after its
parser/decoder has run.

| Log source | Fields |
|---|---|
| `product: linux`, `service: auth` / `cron` | `timestamp`, `program`, `message`, and for sshd `user`, `src_ip` |
| `category: webserver` | Sigma web taxonomy: `cs-method`, `cs-uri-stem`, `cs-uri-query`, `sc-status` |

## Correlation rules

Brute force and password spraying are not visible in a single event, so they
use [Sigma correlation rules](https://sigmahq.io/docs/meta/correlations.html)
on top of the `ssh_failed_password` base rule:

- **Brute force**: `event_count` ≥ 5 per `src_ip` within 1 minute
- **Password spraying**: `value_count` of distinct `user` ≥ 5 per `src_ip`
  within 10 minutes

## Wazuh rules

`wazuh/` contains Wazuh rules and a decoder for the same detections, tested in
a separate CI job (`.github/workflows/wazuh.yml`) against a real
`wazuh/wazuh-manager:4.9.2` container: every raw sample line goes through
`wazuh-logtest`, and the job asserts the expected rule fires on attack
samples and not on benign ones.

| Sigma rule | Wazuh rule(s) | Built-in parent (from the discovery step) |
|---|---|---|
| ssh_failed_password | 100110 existing account, 100114 non-existent | 5760 / 5716, 5710 |
| ssh_bruteforce | 100111, 100115 | correlates on 100110 / 100114 |
| ssh_password_spraying | 100112 (`different_user`), 100113 (`different_srcuser`) | correlates on 100110 / 100114 |
| new_local_user | 100120 | 5902 |
| user_added_to_privileged_group | 100131 | custom `usermod` decoder + 100130, gpasswd 2961 |
| sudo_root_shell | 100140 | 5402 / 5403 |
| crontab_modified | 100150 | 2832 / 2830 |
| sql_injection, path_traversal, sensitive_file_probe, webshell_command_param | 100160 - 100163 | 31100 / 31101 / 31106 / 31108 |

How the rules were built: a discovery step (`run_logtest.py --discover`)
prints which built-in decoder and rule each sample reaches, and every custom
rule hangs off parents observed there, not assumed ones. Things learned the
hard way, now covered by tests:

- In 4.9.2, "Failed password" for an existing user is rule 5760, not 5716.
- `usermod` has no built-in decoder, so its group changes reached no rule.
- The sshd decoder stores existing users in `dstuser` and non-existent ones in
  `srcuser`. Which correlation option counts distinct users was settled by an
  experiment in CI: `different_user` works for `dstuser`; `different_field`
  did not fire; `different_srcuser` also fires when the field is absent, so it
  is only used on events that always carry `srcuser`.
- Wazuh's XML reader does not decode `&amp;`; write `\x26` in patterns.

### Skips and known gaps

These are listed in the samples and printed by every run; nothing is hidden.

- `wazuh_skip` (2 benign cases): "failures spread over N minutes". Wazuh
  correlates on analysis time and `wazuh-logtest` processes all lines at once,
  so time gaps can't be reproduced there. The Python engine tests them.
- `wazuh_gap` (1 case): a spray of 4 existing + 1 non-existent account. The
  two account types are counted separately, so neither reaches 5. The job
  asserts Wazuh still misses it, so it will flag if that ever changes.
- Web requests whose final built-in rule is not one of 31100/31101/31106/31108
  are not covered.

### Running the Wazuh tests locally

```bash
docker run -d --name wazuh wazuh/wazuh-manager:4.9.2
python wazuh/run_logtest.py --wait-only
docker cp wazuh/rules/detection_rules.xml wazuh:/var/ossec/etc/rules/
docker cp wazuh/decoders/detection_decoders.xml wazuh:/var/ossec/etc/decoders/
docker exec wazuh /var/ossec/bin/wazuh-control restart
python wazuh/run_logtest.py            # add --discover to see built-in matches
```

## How the test engine works

[pySigma](https://github.com/SigmaHQ/pySigma) parses each rule into a
condition tree with modifiers (`contains`, `re`, `cased`, ...) already
applied; `detlab/engine.py` walks that tree against an event. Semantics
(case-insensitive, whole-value matching, unanchored regex, missing fields
never match) are pinned down in `tests/test_engine.py`.

The engine supports what these rules use: field/keyword matching, `re`,
`cased`, `null`, numbers, and `event_count` / `value_count` correlations.
Anything else (for example `cidr`, or `temporal` correlations) raises
`UnsupportedFeature` instead of silently not matching.

## Scanning your own logs

```bash
journalctl -o short-iso _COMM=sshd _COMM=sudo --since today | python -m detlab.scan -
python -m detlab.scan /var/log/apache2/access.log
```

It prints every alert (exit code 1 if anything fired). Supported input:
`journalctl -o short-iso`, classic `/var/log/auth.log` syslog and
Apache/Nginx combined access logs.

## Running locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest                       # rules against samples, engine, metadata
sigma check rules/           # Sigma validation
python -m detlab.coverage    # regenerate the coverage table
```

### Adding a rule

1. Write `rules/<area>/<name>.yml` with ATT&CK technique and tactic tags,
   `falsepositives`, and a description explaining the logic and its blind spots.
2. Add `tests/samples/<area>/<name>.yml` with at least one case that must fire
   and one benign case that must not. A case is either a parsed `event` or a
   `raw` log line (a list of lines for correlations).
3. Run `pytest` and `python -m detlab.coverage`.

## Limits

- Most samples are synthetic, written to reflect real log formats; IPs come
  from documentation ranges (RFC 5737). Cases marked `real` come from an
  actual Kali workstation, with hostname and username anonymised.
- Passing tests shows a rule behaves as intended on these samples, not that
  it will be quiet in every environment: tune thresholds and filters against
  your own baseline before alerting on them.

## Roadmap

- Converted Splunk / Elastic queries generated in CI
- Wazuh coverage for more web-accesslog end states

## License

MIT
