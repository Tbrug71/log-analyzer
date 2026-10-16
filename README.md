# SSH Log Analyzer

A small Python tool that reads an SSH authentication log (syslog format,
such as `/var/log/auth.log` or `/var/log/secure`) and flags suspicious
login activity. It is the detection side of security: spotting attacks
in logs, rather than finding vulnerabilities in systems.

Uses only the Python standard library. No installs needed.

## Why I built this

Authentication logs record every login attempt, but nobody reads
thousands of lines by hand. This tool applies a handful of common
detection rules so the lines that matter, like a burst of failed logins
followed by a success, stand out first.

## What it detects

| Rule | What it looks for | Severity |
|------|-------------------|----------|
| Success after failures | A successful login from an IP that was failing repeatedly just before | HIGH |
| Brute force | Many failed logins from one IP in a short window (default: 5 in 10 min) | MEDIUM |
| Username enumeration | One IP trying many nonexistent usernames (default: 4 in 10 min) | MEDIUM |
| Direct root login | A successful SSH login as `root` | MEDIUM |
| Off-hours login | A successful login during unusual hours (default: 00:00-05:00) | LOW |

Loosely, these map to MITRE ATT&CK techniques T1110 (Brute Force) and
T1078 (Valid Accounts).

All thresholds are adjustable from the command line.

## Usage

```bash
python3 log_analyzer.py --input sample_auth.log --year 2026 --output findings.csv
```

Options:

| Option | Default | Meaning |
|--------|---------|---------|
| `--year` | current year | Year of the log (syslog timestamps don't include one) |
| `--fail-threshold` | 5 | Failed logins that count as brute force |
| `--window-minutes` | 10 | Time window used by the rules |
| `--enum-threshold` | 4 | Distinct nonexistent usernames that count as enumeration |
| `--off-hours-start` / `--off-hours-end` | 0 / 5 | Off-hours window (can wrap past midnight, e.g. 22 to 5) |
| `--top` | 15 | Max findings printed to the console |

On Windows, use `py` or `python` instead of `python3`.

## Example output

```
=== SSH Log Analysis Summary ===
Auth events analyzed: 29 (ignored 5 other sshd lines, 0 unparseable)
Findings: 7  (HIGH 1 | MEDIUM 4 | LOW 2)

[HIGH] Success after failures - 203.0.113.45 (user: deploy) at 2026-10-14 03:12:08
       Successful password login as 'deploy' after 12 failed attempts in 10 min from the same IP; possible compromised account
[MEDIUM] Brute force - 203.0.113.45 (user: (multiple)) at 2026-10-14 03:12:08
       12 failed logins within 10 min; users targeted: root, admin, deploy
[MEDIUM] Brute force - 198.51.100.77 (user: (multiple)) at 2026-10-14 14:20:03
       7 failed logins within 10 min; users targeted: test, oracle, ubuntu, postgres, guest
[MEDIUM] Username enumeration - 198.51.100.77 (user: (multiple)) at 2026-10-14 14:20:03
       7 distinct nonexistent usernames tried within 10 min: admin, ftpuser, guest, oracle, postgres, test
[MEDIUM] Direct root login - 192.0.2.30 (user: root) at 2026-10-14 16:05:22
       Successful publickey login as root over SSH; consider setting PermitRootLogin no
[LOW] Off-hours login - 192.0.2.25 (user: bob) at 2026-10-14 02:41:17
       Successful publickey login at 02:41, inside the off-hours window (00:00-05:00)
[LOW] Off-hours login - 203.0.113.45 (user: deploy) at 2026-10-14 03:13:41
       Successful password login at 03:13, inside the off-hours window (00:00-05:00)
```

The full results are also written to a CSV file for sorting and filtering.

## About the sample data

`sample_auth.log` is synthetic. It contains a few planted attack
patterns mixed with normal activity, including a user who mistypes a
password once and then logs in, and an IP that fails only occasionally
across the day. The tool correctly leaves those alone. IP addresses come
from ranges reserved for documentation (RFC 5737), so none of them are
real hosts.

## Limitations

- Handles OpenSSH password and public-key logins only
- Syslog timestamps have no year, so logs that span New Year need to be split
- Detection is rule-based and threshold-based, so it can miss slow
  attacks or flag legitimate bursts such as a script with a bad password

## Possible next steps

- Support `journalctl` output and other log formats
- Add IP reputation or geolocation lookups
- JSON output and alerting for new HIGH findings
- Track repeat offenders across multiple log files

## About

Built by Thomas Verbrugge as part of a hands-on cybersecurity portfolio,
alongside a B.S. in Cyber and Data Security and a background in
enterprise infrastructure. Built and tested against sample data only.
