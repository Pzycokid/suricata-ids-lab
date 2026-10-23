"""
Summarise Suricata alerts from eve.json into a short triage report.

    python3 tools/eve_summary.py /var/log/suricata/eve.json
    python3 tools/eve_summary.py eve.json --json     # machine-readable (e.g. for BlueShield)

Groups alerts by signature and by source IP, so an analyst sees "who is doing what" at a glance.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict


def load_alerts(path: str) -> list[dict]:
    alerts = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue  # skip truncated lines from a log being written
            if event.get("event_type") == "alert":
                alerts.append(event)
    return alerts


def summarise(alerts: list[dict]) -> dict:
    by_sig = Counter(a["alert"]["signature"] for a in alerts)
    by_src: dict[str, Counter] = defaultdict(Counter)
    severity: dict[str, int] = {}
    for a in alerts:
        sig = a["alert"]["signature"]
        by_src[a.get("src_ip", "?")][sig] += 1
        severity[sig] = a["alert"].get("severity", 3)
    return {
        "total_alerts": len(alerts),
        "by_signature": [
            {"signature": s, "count": n, "severity": severity[s]}
            for s, n in sorted(by_sig.items(), key=lambda kv: (severity[kv[0]], -kv[1]))
        ],
        "by_source": [
            {"src_ip": ip, "alerts": sum(c.values()), "signatures": sorted(c)}
            for ip, c in sorted(by_src.items(), key=lambda kv: -sum(kv[1].values()))
        ],
    }


def to_text(summary: dict) -> str:
    out = [f"Suricata alert summary: {summary['total_alerts']} alerts", "", "By signature (most severe first):"]
    for row in summary["by_signature"]:
        out.append(f"  [sev {row['severity']}] {row['count']:>4}  {row['signature']}")
    out += ["", "By source IP:"]
    for row in summary["by_source"]:
        out.append(f"  {row['src_ip']:<15} {row['alerts']:>4} alerts  ->  " + "; ".join(row["signatures"]))
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("eve", help="path to Suricata eve.json")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    args = ap.parse_args(argv)
    summary = summarise(load_alerts(args.eve))
    print(json.dumps(summary, indent=2) if args.json else to_text(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
