# Detection Engineering

> Sigma detection rules for Linux and web-server attacks, mapped to MITRE ATT&CK and
> **tested in CI**: every rule has attack samples it must catch and benign samples it
> must ignore.

[![ci](https://github.com/defamp/detection-engineering/actions/workflows/ci.yml/badge.svg)](https://github.com/defamp/detection-engineering/actions/workflows/ci.yml)

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
tests/                    sample, engine and metadata tests
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
   and one benign case that must not.
3. Run `pytest` and `python -m detlab.coverage`.

## Limits

- Samples are synthetic, written to reflect real log formats; IPs come from
  documentation ranges (RFC 5737).
- Passing tests shows a rule behaves as intended on these samples, not that
  it will be quiet in every environment: tune thresholds and filters against
  your own baseline before alerting on them.

## Roadmap

- Wazuh rules and decoders for the same detections, tested with `wazuh-logtest`
- Converted Splunk / Elastic queries generated in CI

## License

MIT
