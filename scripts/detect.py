#!/usr/bin/env python3
"""Detection rules over the Tatou audit log (Specialization D).

Reads the line-delimited JSON produced by the "tatou.audit" logger and reports
attacks that no single event reveals. The audit log records *events*; this
script turns them into *incidents*, because a failed login is normal and forty
failed logins from one address in a minute is not.

    python scripts/detect.py --log audit.log
    docker compose logs server | python scripts/detect.py --stdin

Design notes
------------
* Each rule states the threat it covers (T-xx) from the threat model, so the
  output can be read against the model rather than as a pile of grep hits.
* Thresholds are deliberately conservative. A rule that fires on normal use is
  worse than no rule: it trains the operator to ignore the output.
* The script only reports; it never blocks. Blocking is the wrong reaction here
  - see section 6.1 of the threat model, where we explain why automatic
  lockout on a public endpoint is itself a denial-of-service vector.
* A finding is not a certainty. The exit code is 0 when nothing crossed a
  threshold, 1 when something did, so it can be used from cron or CI.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta

# --- thresholds -------------------------------------------------------
LOGIN_FAILURES_PER_IP = 5        # T-10: password spraying / brute force
LOGIN_WINDOW = timedelta(minutes=5)
AUTH_FAILURES_PER_IP = 10        # T-01: token forging or enumeration
AUTH_WINDOW = timedelta(minutes=5)
UPLOAD_REJECTIONS_PER_IP = 3     # T-06/T-07: probing the upload path
UPLOAD_WINDOW = timedelta(minutes=10)
RMAP_FAILURES_PER_IP = 5         # T-22/T-25: protocol abuse or replay
RMAP_WINDOW = timedelta(minutes=10)
BURST_WINDOW = timedelta(seconds=30)  # many auth failures for many paths = scanning
BURST_MIN_EVENTS = 8


def parse_ts(value: str) -> datetime:
    # The logger writes ISO-8601 with a trailing "Z"-equivalent offset.
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def load(stream) -> list[dict]:
    """Parse the log, skipping anything that is not an audit record.

    The container log mixes gunicorn's access log and Flask's own output with
    ours, so a line that does not parse is expected, not exceptional. We count
    those and report them, rather than failing or silently dropping them.
    """
    events, skipped = [], 0
    for line in stream:
        line = line.strip()
        if not line or "{" not in line:
            continue
        # Docker prefixes each line with a timestamp; keep the JSON tail.
        start = line.find("{")
        # A JSON object may be embedded in a longer line (docker logs prefix);
        # take the widest balanced object we can parse.
        candidate = line[start:]
        obj = None
        try:
            obj = json.loads(candidate)
        except json.JSONDecodeError:
            end = candidate.rfind("}")
            if end > 0:
                try:
                    obj = json.loads(candidate[: end + 1])
                except json.JSONDecodeError:
                    obj = None
        if not isinstance(obj, dict) or "event" not in obj or "ts" not in obj:
            skipped += 1
            continue
        try:
            obj["_ts"] = parse_ts(obj["ts"])
        except (ValueError, TypeError):
            skipped += 1
            continue
        events.append(obj)
    if skipped:
        print(f"[info] {skipped} non-audit lines ignored (access log, tracebacks)",
              file=sys.stderr)
    return events


def _windowed(events, predicate, key, threshold, window):
    """Yield (key, total, win_count, first_seen, last_seen) for groups that
    crossed the threshold.

    `total` is how many matching events the key produced overall; `win_count`
    is the size of the dense window that tripped the rule. Reporting both keeps
    the finding honest: "5 in a minute, 61 today" says something different from
    "5 in a minute" alone.
    """
    buckets: dict[str, list[datetime]] = defaultdict(list)
    for ev in events:
        if predicate(ev):
            buckets[str(ev.get(key))].append(ev["_ts"])
    for name, times in buckets.items():
        times.sort()
        total = len(times)
        for i in range(total - threshold + 1):
            span = times[i + threshold - 1] - times[i]
            if span <= window:
                yield name, total, threshold, times[i], times[i + threshold - 1], span
                break


def analyse(events: list[dict]) -> list[str]:
    findings: list[str] = []
    n = lambda ev, name: ev.get("event") == name  # noqa: E731

    # T-10 - password spraying against the login endpoint.
    for ip, total, cnt, first, last, span in _windowed(
        events, lambda e: n(e, "login.failure"), "ip", LOGIN_FAILURES_PER_IP, LOGIN_WINDOW
    ):
        findings.append(
            f"[T-10] {cnt} failed logins from {ip} within {span} "
            f"({first:%H:%M:%S}-{last:%H:%M:%S}), {total} total"
            f" - likely password spraying"
        )

    # T-01 - token forging, or enumeration of protected endpoints.
    for ip, total, cnt, first, last, span in _windowed(
        events, lambda e: n(e, "auth.failure"), "ip", AUTH_FAILURES_PER_IP, AUTH_WINDOW
    ):
        findings.append(
            f"[T-01] {cnt} authentication failures from {ip} within {span}, "
            f"{total} total - token forging or endpoint enumeration"
        )

    # T-06 / T-07 - someone is probing the upload validation.
    for ip, total, cnt, first, last, span in _windowed(
        events, lambda e: n(e, "upload.rejected"), "ip",
        UPLOAD_REJECTIONS_PER_IP, UPLOAD_WINDOW,
    ):
        findings.append(
            f"[T-06] {cnt} rejected uploads from {ip} within {span}, {total} total"
            f" - probing filename handling or the PDF check"
        )

    # T-22 / T-25 - RMAP abuse.
    for ip, total, cnt, first, last, span in _windowed(
        events, lambda e: n(e, "rmap.initiate.rejected") or n(e, "rmap.getlink.rejected"),
        "ip", RMAP_FAILURES_PER_IP, RMAP_WINDOW,
    ):
        findings.append(
            f"[T-22] {cnt} RMAP failures from {ip} within {span}, {total} total"
            f" - replay, identity probing, or forced watermarking runs"
        )

    # Broad scanning - many auth failures across many distinct paths, fast.
    bursts: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        if ev.get("event") == "auth.failure":
            bursts[str(ev.get("ip"))].append(ev)
    for ip, evs in bursts.items():
        evs.sort(key=lambda e: e["_ts"])
        for i in range(len(evs) - BURST_MIN_EVENTS + 1):
            span = evs[i + BURST_MIN_EVENTS - 1]["_ts"] - evs[i]["_ts"]
            if span <= BURST_WINDOW:
                paths = {e.get("path") for e in evs[i : i + BURST_MIN_EVENTS]}
                if len(paths) >= 3:
                    findings.append(
                        f"[T-01] burst of {BURST_MIN_EVENTS} auth failures from {ip} "
                        f"across {len(paths)} paths in {span} - automated scanning"
                    )
                break

    # Traversal attempts get their own finding, but one per distinct source +
    # filename, not one per event: five identical lines say nothing that one
    # line with a count does not, and repetition trains the reader to skim.
    traversal: dict[tuple, int] = defaultdict(int)
    for ev in events:
        if (ev.get("event") == "upload.rejected"
                and ev.get("reason") == "path_traversal_or_unsafe_name"):
            traversal[(ev.get("ip"), ev.get("raw_filename"))] += 1
    for (ip, raw_name), count in traversal.items():
        findings.append(
            f"[T-06] traversal-shaped filename rejected from {ip} "
            f"({count}x): {raw_name!r}"
        )
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--log", help="path to the audit log")
    ap.add_argument("--stdin", action="store_true", help="read from standard input")
    ap.add_argument("--summary", action="store_true",
                    help="also print a per-event count table")
    args = ap.parse_args()

    if args.stdin:
        events = load(sys.stdin)
    elif args.log:
        with open(args.log, encoding="utf-8", errors="replace") as fh:
            events = load(fh)
    else:
        ap.error("provide --log PATH or --stdin")

    if args.summary:
        counts: dict[str, int] = defaultdict(int)
        for ev in events:
            counts[ev["event"]] += 1
        print("--- event counts ---")
        for name in sorted(counts):
            print(f"  {name:28s} {counts[name]}")
        print()

    findings = analyse(events)
    if not findings:
        print(f"no findings across {len(events)} audit events")
        return 0
    for line in findings:
        print(f"FINDING  {line}")
    print(f"\n{len(findings)} finding(s) across {len(events)} audit events")
    return 1


if __name__ == "__main__":
    sys.exit(main())
