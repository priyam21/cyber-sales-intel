"""How do we know the ranking works? There are no "will buy" labels in a scan file, so we test the
two properties a ranking must have, using only data it never saw:

1. Predictive validity (held-out label). Companies with an *observed compromise* (C2/malware/
   'compromised' tag on their own asset) are the closest thing to ground truth for "needs help
   now". We rescore every company with the compromise signal removed and ask: do the remaining
   signals rank those companies above the rest? Reported as ROC-AUC and lift in the top decile,
   next to a naive baseline (rank by attack-surface size) — the score must beat "just pick big ones".

2. Reliability (split-half). A company-level property should not depend on which of its hosts
   happened to be scanned. Split each company's IPs into two halves by hash, score each half
   independently, and report the Spearman correlation and tier agreement.

Usage: python -I pipeline/evaluate.py data/out
"""
from __future__ import annotations

import json
import math
import os
import sys
from pathlib import Path

import duckdb

sys.path.insert(0, str(Path(__file__).resolve().parent))
from score import SIGNALS  # noqa: E402


def need_from(row: dict, exclude: set[str]) -> float:
    raw = sum(pts for k, (pts, _) in SIGNALS.items() if k not in exclude and row.get(f"s_{k}"))
    return 100 * (1 - math.exp(-raw / 70))


def auc(scores: list[float], labels: list[int]) -> float:
    # Mann-Whitney U with average ranks for ties
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2 + 1
        i = j + 1
    pos = sum(labels)
    neg = len(labels) - pos
    if not pos or not neg:
        return float("nan")
    return (sum(r for r, y in zip(ranks, labels) if y) - pos * (pos + 1) / 2) / (pos * neg)


def auc_ci(a: float, pos: int, neg: int) -> list[float]:
    """95% CI via Hanley & McNeil (1982) — honest about how few positives we have."""
    q1, q2 = a / (2 - a), 2 * a * a / (1 + a)
    se = math.sqrt((a * (1 - a) + (pos - 1) * (q1 - a * a) + (neg - 1) * (q2 - a * a)) / (pos * neg))
    return [round(max(0.0, a - 1.96 * se), 3), round(min(1.0, a + 1.96 * se), 3)]


def heldout(rows: list[dict], label: str, exclude: set[str]) -> dict:
    y = [int(bool(r[f"s_{label}"])) for r in rows]
    s = [need_from(r, exclude | {label}) for r in rows]
    size = [math.log1p(r["ips"] or 0) for r in rows]
    pos, neg = sum(y), len(y) - sum(y)
    a, b = auc(s, y), auc(size, y)
    return {
        "label": label, "signals_withheld": sorted(exclude | {label}), "positives": pos, "base_rate": pos / len(y),
        "auc_score": round(a, 3), "auc_score_95ci": auc_ci(a, pos, neg),
        "auc_size_baseline": round(b, 3), "auc_size_baseline_95ci": auc_ci(b, pos, neg),
        "lift_top10pct_score": round(lift_top(s, y), 2), "lift_top10pct_size_baseline": round(lift_top(size, y), 2),
    }


def lift_top(scores: list[float], labels: list[int], frac: float = 0.1) -> float:
    n = max(1, int(len(scores) * frac))
    top = sorted(range(len(scores)), key=lambda i: -scores[i])[:n]
    base = sum(labels) / len(labels)
    return (sum(labels[i] for i in top) / n) / base if base else float("nan")


def spearman(a: list[float], b: list[float]) -> float:
    def rank(x):
        o = sorted(range(len(x)), key=lambda i: x[i])
        r = [0.0] * len(x)
        for pos, i in enumerate(o):
            r[i] = pos
        return r
    ra, rb = rank(a), rank(b)
    n = len(a)
    ma, mb = sum(ra) / n, sum(rb) / n
    cov = sum((x - ma) * (y - mb) for x, y in zip(ra, rb))
    va = math.sqrt(sum((x - ma) ** 2 for x in ra))
    vb = math.sqrt(sum((y - mb) ** 2 for y in rb))
    return cov / (va * vb) if va and vb else float("nan")


SIGNAL_COLS = {k: None for k in SIGNALS}


def main(out: str) -> None:
    con = duckdb.connect(os.path.join(out, "scoring.duckdb"), read_only=True)
    cols = ["entity", "ips"] + [f"s_{k}" for k in SIGNALS]
    rows = [dict(zip(cols, r)) for r in con.execute(f"select {','.join(cols)} from companies order by entity").fetchall()]
    report: dict = {"companies": len(rows)}

    # --- 1. held-out labels ---------------------------------------------------------------
    y = [int(bool(r["s_compromised"])) for r in rows]
    report["heldout_compromise"] = heldout(rows, "compromised", set())
    # Second, larger test: do the *non-CVE* signals (exposure + hygiene) predict a vulnerability the
    # scanner actively confirmed? All CVE-derived signals are withheld so nothing leaks.
    report["heldout_verified_vuln"] = heldout(
        rows, "verified_cve", {"kev_cve", "kev_edge", "ransomware_cve", "high_epss", "ambient_kev", "heartbleed", "compromised"})
    # Per-signal lift: which individual signals co-occur with compromise most (feeds weight review)
    per = {}
    for k in SIGNALS:
        if k == "compromised":
            continue
        has = [i for i, r in enumerate(rows) if r[f"s_{k}"]]
        if len(has) >= 20:
            rate = sum(y[i] for i in has) / len(has)
            per[k] = {"companies": len(has), "compromise_rate": round(rate, 4),
                      "lift_vs_base": round(rate / (sum(y) / len(y)), 2) if sum(y) else None}
    report["signal_lift_vs_compromise"] = dict(sorted(per.items(), key=lambda kv: -(kv[1]["lift_vs_base"] or 0)))

    # --- 2. split-half reliability -----------------------------------------------------------
    sig_sql = ",".join(
        f"bool_or({expr}) as s_{k}" for k, expr in {
            "compromised": "compromised or malicious", "ransomware_cve": "len(ransomware_cves)>0",
            "kev_cve": "len(kev_cves)>0", "verified_cve": "len(verified_cves)>0", "db_no_auth": "db_no_auth",
            "remote_access": "risky_service in ('rdp','smb','telnet','vnc','winrm','netbios','docker','kubernetes')",
            "ics": "ics", "high_epss": "max_epss>=0.5", "db_open": "db_open is not null", "eol": "eol",
            "ai_exposed": "ai_exposed", "edge_device": "edge_device", "open_dir": "open_dir",
            "ntlm_leak": "ntlm_domain is not null", "cert_expired": "cert_expired", "weak_tls": "weak_tls",
            "self_signed": "cert_self_signed", "ambient_kev": "len(ambient_kevs)>0",
        }.items())
    halves = con.execute(f"""
        with h as (select *, hash(ip) % 2 as half from banners_clean
                   where entity in (select entity from companies where ips >= 4))
        select entity, half, {sig_sql} from h group by entity, half order by entity, half""").fetchall()
    hcols = ["entity", "half"] + [f"s_{k}" for k in [
        "compromised", "ransomware_cve", "kev_cve", "verified_cve", "db_no_auth", "remote_access", "ics",
        "high_epss", "db_open", "eol", "ai_exposed", "edge_device", "open_dir", "ntlm_leak", "cert_expired",
        "weak_tls", "self_signed", "ambient_kev"]]
    by: dict[str, dict[int, float]] = {}
    for r in halves:
        d = dict(zip(hcols, r))
        by.setdefault(d["entity"], {})[d["half"]] = need_from(d, set())
    pairs = [(v[0], v[1]) for v in by.values() if 0 in v and 1 in v]
    tier = lambda x: 2 if x >= 60 else 1 if x >= 35 else 0  # noqa: E731
    report["split_half"] = {
        "companies_with_4plus_ips": len(pairs),
        "spearman_need": round(spearman([a for a, _ in pairs], [b for _, b in pairs]), 3),
        "tier_agreement": round(sum(tier(a) == tier(b) for a, b in pairs) / max(1, len(pairs)), 3),
    }
    # --- 3. precision audit of the top of the list (labels in eval/, made by the coding agent) --
    audit = Path(__file__).resolve().parents[1] / "eval" / "precision_audit_top50.csv"
    app_path = os.path.join(out, "app_data.json")
    if audit.exists() and os.path.exists(app_path):
        import csv
        # labels are keyed by entity and applied to the *current* ranking, so a rescore cannot reuse stale order
        labels = {r["entity"]: int(r["is_real_prospect"]) for r in csv.DictReader(open(audit))}
        named = [a["entity"] for a in json.load(open(app_path))["accounts"] if not a["entity"].startswith("org:")]
        top = named[:50]
        report["precision_audit"] = {f"p_at_{k}": round(sum(labels.get(e, 0) for e in top[:k]) / k, 2)
                                     for k in (10, 20, 50) if len(top) >= k}
        report["precision_audit"]["unlabelled_in_top50"] = [e for e in top if e not in labels]
        report["precision_audit"]["labeler"] = "Claude (coding agent), from evidence in the app; see eval/precision_audit_top50.csv"
    with open(os.path.join(out, "evaluation.json"), "w") as fh:
        json.dump(report, fh, indent=1)
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main(sys.argv[1])
