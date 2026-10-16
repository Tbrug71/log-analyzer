#!/usr/bin/env python3
"""
log_analyzer.py

Parses SSH authentication logs (syslog format, such as /var/log/auth.log or
/var/log/secure) and flags suspicious login activity:

  1. Brute force            - many failed logins from one IP in a short window
  2. Username enumeration   - one IP trying many different nonexistent usernames
  3. Success after failures - a successful login from an IP that was just failing
  4. Off-hours login        - successful logins during unusual hours
  5. Direct root login      - successful SSH login as root

Usage:
    python3 log_analyzer.py --input sample_auth.log --year 2026 --output findings.csv

Uses only the Python standard library.
"""

import argparse
import csv
import re
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

# Syslog line: "Oct 14 03:12:08 web-01 sshd[2211]: <message>"
LINE_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
FAILED_RE = re.compile(
    r"Failed password for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port \d+"
)

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def parse_args():
    parser = argparse.ArgumentParser(description="Detect suspicious SSH login activity in an auth log.")
    parser.add_argument("--input", required=True, help="Path to the auth log (syslog format)")
    parser.add_argument("--output", default="findings.csv", help="Path to write the findings CSV")
    parser.add_argument("--year", type=int, default=datetime.now().year,
                        help="Year of the log (syslog timestamps do not include one). Default: current year")
    parser.add_argument("--fail-threshold", type=int, default=5,
                        help="Failed logins from one IP within the window that count as brute force (default 5)")
    parser.add_argument("--window-minutes", type=int, default=10,
                        help="Time window in minutes used by the detection rules (default 10)")
    parser.add_argument("--enum-threshold", type=int, default=4,
                        help="Distinct nonexistent usernames from one IP that count as enumeration (default 4)")
    parser.add_argument("--off-hours-start", type=int, default=0,
                        help="First hour (0-23) treated as off-hours (default 0)")
    parser.add_argument("--off-hours-end", type=int, default=5,
                        help="Hour (0-23) at which off-hours end, exclusive (default 5)")
    parser.add_argument("--top", type=int, default=15, help="Max findings to print to the console (default 15)")
    return parser.parse_args()


def parse_log(path, year):
    """Return (events, ignored_count, unparseable_count) from an auth log."""
    events = []
    ignored = 0   # sshd lines we don't use (sessions, disconnects, ...)
    skipped = 0   # lines that are not sshd syslog lines at all
    with open(path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            m = LINE_RE.match(line)
            if not m:
                skipped += 1
                continue
            try:
                when = datetime.strptime(f"{year} {' '.join(m['ts'].split())}", "%Y %b %d %H:%M:%S")
            except ValueError:
                skipped += 1
                continue

            msg = m["msg"]
            failed = FAILED_RE.search(msg)
            if failed:
                events.append({
                    "time": when, "kind": "fail", "user": failed["user"], "ip": failed["ip"],
                    "invalid": bool(failed["invalid"]), "method": "password",
                })
                continue
            accepted = ACCEPTED_RE.search(msg)
            if accepted:
                events.append({
                    "time": when, "kind": "success", "user": accepted["user"], "ip": accepted["ip"],
                    "invalid": False, "method": accepted["method"],
                })
                continue
            ignored += 1

    events.sort(key=lambda e: e["time"])
    return events, ignored, skipped


def minutes(delta):
    return int(delta.total_seconds() // 60)


def fmt(when):
    return when.strftime("%Y-%m-%d %H:%M:%S")


def make_finding(severity, rule, ip, user, first, last, count, details):
    return {
        "severity": severity, "rule": rule, "source_ip": ip, "user": user,
        "first_seen": first, "last_seen": last, "count": count, "details": details,
    }


def densest_window(times, window, threshold):
    """Largest group of events inside one time window, or None if below threshold."""
    times = sorted(times)
    best = None
    left = 0
    for right in range(len(times)):
        while times[right] - times[left] > window:
            left += 1
        count = right - left + 1
        if count >= threshold and (best is None or count > best[2]):
            best = (times[left], times[right], count)
    return best


def distinct_window(items, window, threshold):
    """Most distinct usernames seen inside one time window, or None if below threshold."""
    items = sorted(items)
    counts = {}
    left = 0
    best = None
    for right, (when, name) in enumerate(items):
        counts[name] = counts.get(name, 0) + 1
        while when - items[left][0] > window:
            old = items[left][1]
            counts[old] -= 1
            if counts[old] == 0:
                del counts[old]
            left += 1
        if len(counts) >= threshold and (best is None or len(counts) > best[2]):
            best = (items[left][0], when, len(counts), sorted(counts))
    return best


def detect_brute_force(events, window, threshold):
    fail_times = defaultdict(list)
    users = defaultdict(Counter)
    for e in events:
        if e["kind"] == "fail":
            fail_times[e["ip"]].append(e["time"])
            users[e["ip"]][e["user"]] += 1

    findings = []
    for ip, times in fail_times.items():
        hit = densest_window(times, window, threshold)
        if hit:
            start, end, count = hit
            targeted = [u for u, _ in users[ip].most_common(5)]
            findings.append(make_finding(
                "MEDIUM", "Brute force", ip,
                targeted[0] if len(users[ip]) == 1 else "(multiple)",
                start, end, count,
                f"{count} failed logins within {minutes(window)} min; users targeted: {', '.join(targeted)}",
            ))
    return findings


def detect_enumeration(events, window, threshold):
    invalid = defaultdict(list)
    for e in events:
        if e["kind"] == "fail" and e["invalid"]:
            invalid[e["ip"]].append((e["time"], e["user"]))

    findings = []
    for ip, items in invalid.items():
        hit = distinct_window(items, window, threshold)
        if hit:
            start, end, n, names = hit
            findings.append(make_finding(
                "MEDIUM", "Username enumeration", ip, "(multiple)", start, end, n,
                f"{n} distinct nonexistent usernames tried within {minutes(window)} min: {', '.join(names[:6])}",
            ))
    return findings


def detect_success_after_failures(events, window, threshold):
    fail_times = defaultdict(list)
    for e in events:  # events are already sorted by time
        if e["kind"] == "fail":
            fail_times[e["ip"]].append(e["time"])

    findings = []
    for e in events:
        if e["kind"] != "success":
            continue
        times = fail_times.get(e["ip"], [])
        lo = bisect_left(times, e["time"] - window)
        hi = bisect_right(times, e["time"])
        recent = times[lo:hi]
        if len(recent) >= threshold:
            findings.append(make_finding(
                "HIGH", "Success after failures", e["ip"], e["user"], recent[0], e["time"], len(recent),
                f"Successful {e['method']} login as '{e['user']}' after {len(recent)} failed attempts "
                f"in {minutes(window)} min from the same IP; possible compromised account",
            ))
    return findings


def in_off_hours(hour, start, end):
    if start <= end:
        return start <= hour < end
    return hour >= start or hour < end  # window wraps past midnight


def detect_off_hours(events, start, end):
    findings = []
    for e in events:
        if e["kind"] == "success" and in_off_hours(e["time"].hour, start, end):
            findings.append(make_finding(
                "LOW", "Off-hours login", e["ip"], e["user"], e["time"], e["time"], 1,
                f"Successful {e['method']} login at {e['time'].strftime('%H:%M')}, "
                f"inside the off-hours window ({start:02d}:00-{end:02d}:00)",
            ))
    return findings


def detect_root_login(events):
    findings = []
    for e in events:
        if e["kind"] == "success" and e["user"] == "root":
            findings.append(make_finding(
                "MEDIUM", "Direct root login", e["ip"], "root", e["time"], e["time"], 1,
                f"Successful {e['method']} login as root over SSH; consider setting PermitRootLogin no",
            ))
    return findings


def write_report(findings, path):
    fields = ["severity", "rule", "source_ip", "user", "first_seen", "last_seen", "count", "details"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for item in findings:
            row = dict(item)
            row["first_seen"] = fmt(item["first_seen"])
            row["last_seen"] = fmt(item["last_seen"])
            writer.writerow(row)


def print_summary(findings, events, ignored, skipped, top):
    by_sev = Counter(f["severity"] for f in findings)
    print("\n=== SSH Log Analysis Summary ===")
    print(f"Auth events analyzed: {len(events)} (ignored {ignored} other sshd lines, {skipped} unparseable)")
    print(f"Findings: {len(findings)}  "
          f"(HIGH {by_sev.get('HIGH', 0)} | MEDIUM {by_sev.get('MEDIUM', 0)} | LOW {by_sev.get('LOW', 0)})\n")
    for item in findings[:top]:
        print(f"[{item['severity']}] {item['rule']} - {item['source_ip']} "
              f"(user: {item['user'] or '-'}) at {fmt(item['first_seen'])}")
        print(f"       {item['details']}")
    if len(findings) > top:
        print(f"\n... and {len(findings) - top} more in the report file")
    print()


def main():
    args = parse_args()
    if args.window_minutes <= 0:
        raise SystemExit("--window-minutes must be greater than 0")
    input_path = Path(args.input)
    if not input_path.exists():
        raise SystemExit(f"Input file not found: {input_path}")

    window = timedelta(minutes=args.window_minutes)
    events, ignored, skipped = parse_log(input_path, args.year)

    findings = []
    findings += detect_brute_force(events, window, args.fail_threshold)
    findings += detect_enumeration(events, window, args.enum_threshold)
    findings += detect_success_after_failures(events, window, args.fail_threshold)
    findings += detect_off_hours(events, args.off_hours_start, args.off_hours_end)
    findings += detect_root_login(events)
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["first_seen"]))

    write_report(findings, args.output)
    print_summary(findings, events, ignored, skipped, args.top)
    print(f"Full findings report written to: {args.output}")


if __name__ == "__main__":
    main()
