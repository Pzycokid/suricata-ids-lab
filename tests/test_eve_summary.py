from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from eve_summary import load_alerts, summarise  # noqa: E402

SAMPLE = Path(__file__).with_name("sample_eve.json")


def test_sample_contains_lab_alerts():
    alerts = load_alerts(SAMPLE)
    sigs = {a["alert"]["signature"] for a in alerts}
    assert "LAB RECON Possible TCP SYN port scan" in sigs
    assert "LAB CRED Possible SSH brute force" in sigs


def test_summary_groups_by_source():
    s = summarise(load_alerts(SAMPLE))
    scanner = next(r for r in s["by_source"] if r["src_ip"] == "10.0.0.66")
    assert "LAB RECON ICMP ping sweep" in scanner["signatures"]
    assert s["total_alerts"] == sum(r["count"] for r in s["by_signature"])
