"""Stage 2 — aggregate banner facts to companies, score them, and export the app dataset.

Score = Need (how acute the security pain is) blended with Fit (is this a real, reachable business
big enough to buy) and lifted by Timing (why this week rather than next quarter).

Usage:
    python -I pipeline/score.py data/facts data/out [--top 6000]
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from pathlib import Path

import duckdb

sys.path.insert(0, str(Path(__file__).resolve().parent))
from entity import registrable  # noqa: E402
from segments import classify  # noqa: E402

# Need-signal weights: points per company when the signal is present (not per host — one exposed
# RDP box is as good a conversation starter as fifty). Grouped into the sales "plays" they unlock.
SIGNALS = {
    #  key                 points  play
    "compromised":        (40, "Active compromise"),
    "ransomware_cve":     (32, "Ransomware-linked vulnerability"),
    "kev_edge":           (30, "Exploited perimeter device"),
    "verified_cve":       (28, "Known-exploited vulnerability"),
    "kev_cve":            (22, "Known-exploited vulnerability"),
    "db_no_auth":         (24, "Exposed data store"),
    "heartbleed":         (18, "Known-exploited vulnerability"),
    "remote_access":      (16, "Exposed remote access"),
    "ics":                (16, "OT / ICS exposure"),
    "high_epss":          (12, "Known-exploited vulnerability"),
    "db_open":            (10, "Exposed data store"),
    "eol":                (10, "End-of-life infrastructure"),
    "ai_exposed":         (10, "AI / MCP exposure"),
    "edge_device":        (6,  "Exploited perimeter device"),
    "open_dir":           (6,  "Exposed data store"),
    "ntlm_leak":          (6,  "Security hygiene gaps"),
    "cert_expired":       (6,  "Security hygiene gaps"),
    "weak_tls":           (5,  "Security hygiene gaps"),
    "self_signed":        (3,  "Security hygiene gaps"),
    "no_waf":             (3,  "Security hygiene gaps"),
    "ambient_kev":        (4,  "Security hygiene gaps"),
    "missing_headers":    (2,  "Security hygiene gaps"),
}
# A KEV CVE matched on more banners than this is "ambient": inferred from a version string on
# commodity web servers (HTTP/2 Rapid Reset on every nginx, Apache mod_rewrite...). Distros backport
# fixes without bumping versions, so these are mostly false positives -> hygiene signal only,
# unless the scanner actively verified the specific host.
AMBIENT_KEV_BANNERS = 1000
# Consumer / CPE device fingerprints: their density marks an access-ISP netblock.
CPE_PAT = (r"tr-069|cwmp|home gateway|hikvision|dahua|dvr|nvr|ip camera|chromecast|plex|mikrotik|upnp|"
           r"\bsip\b|zte|huawei|router|gpon|fritz|tp-link|netis|boa |micro_httpd|rompager|goahead|realtek|"
           r"broadband|cpe|dropbear|busybox|ubiquiti|airos|draytek|zyxel|sonos|roku|smart tv|printer")
# Netblock names that describe address pools, not companies.
GENERIC_ORG = (r"^org:(.*\b(addresses|address|dhcp|clients?|customers?|subscribers?|region|infrastructure|"
               r"pool|range|block|nat|cgnat|lte|gprs|adsl|ftth|vdsl|hotspot|users|row|backbone|"
               r"reserved|hoster|hosting|szerver|server|dedik|dedicated|vds|vps|kabel|online|layer|net|"
               r"networks?|communications?|telecom|broadband|datacenter|cloud|isp|wifi|fibra|fiber)\b.*|"
               r"company [0-9a-z]+|[a-z0-9 ]{1,3})$")
REMOTE = ("rdp", "smb", "telnet", "vnc", "winrm", "netbios", "docker", "kubernetes")

AGG_SQL = """
create or replace table banners as
select * exclude (honeypot) from read_parquet('{facts}/**/*.parquet', hive_partitioning=true)
where entity is not null and not honeypot;

-- Data-driven infra filter. Whoever owns the netblock is not necessarily who runs the box:
-- ISPs (customers' routers/cameras), hosting providers (other companies' sites) and shared
-- default certs would otherwise top every ranking. Calibrated on known cases: access ISPs show
-- 8-42% consumer-device banners vs <=1% for enterprises; hosting orgs carry >=10 other companies'
-- certs on their IPs vs ~1 for an enterprise.
create or replace table orgstats as
select org,
  count(distinct entity) filter (where entity_src in ('cert','http_host'))           as hosted_domains,
  avg(regexp_matches(lower(coalesce(product,'') || ' ' || module), '{cpe}')::int)    as cpe_share,
  count(distinct asn)                                                                 as asns
from read_parquet('{facts}/**/*.parquet', hive_partitioning=true) group by org;

create or replace table entstats as
select entity, count(distinct ip) ips, count(distinct org) orgs,
  avg(case when entity_src = 'rdns' then 1 else 0 end) rdns_share,
  sum(case when entity_src = 'cert' then 1 else 0 end) cert_rows,
  avg(regexp_matches(lower(coalesce(product,'') || ' ' || module), '{cpe}')::int) cpe_share,
  bool_or(entity_src = 'whois_org') is_org,
  avg(generic_host::int) filter (where hostname is not null) generic_host_share,
  -- hostname templates per IP: 'host-NNN.dedicated.vsys.host' x 417 IPs = 1 template. Providers
  -- stamp names from a template (<=0.11 observed); organisations name hosts by function (>=0.43).
  count(distinct regexp_replace(regexp_replace(lower(hostname), '[^.]*[0-9][^.]*', '#', 'g'), '^[^.]{{1,2}}\\.', '#.'))
    / count(distinct ip) tpl_per_ip
from banners group by entity;

create or replace table infra as
select entity, 'rdns-namespace' as why from entstats
  where ips >= 25 and rdns_share > 0.8 and cert_rows = 0
union select entity, 'consumer-device fleet' from entstats
  where ips >= 50 and cpe_share >= 0.15
union select entity, 'shared across many networks' from entstats
  where orgs >= 25
union select distinct b.entity, 'org is ISP/hosting' from banners b join orgstats o using (org)
  where b.entity_src = 'whois_org' and (o.cpe_share >= 0.08 or o.hosted_domains >= 10 or o.asns >= 5)
union select entity, 'generic netblock name' from entstats
  where is_org and regexp_matches(entity, '{generic}')
-- A provider's own reverse-DNS namespace: many IPs, named via rDNS, hosts machine-numbered
-- (vps1234.provider.net) rather than named by function (vpn.company.com).
union select entity, 'provider rDNS namespace' from entstats
  where not is_org and ips >= 10 and rdns_share >= 0.5 and generic_host_share >= 0.5
union select entity, 'templated hostnames' from entstats
  where not is_org and ips >= 20 and rdns_share >= 0.5 and tpl_per_ip <= 0.15
union select entity, 'provider-like name' from entstats
  where not is_org and ips >= 10
    and regexp_matches(split_part(entity, '.', 1), 'host|server|vps|dedi|colo|datacenter|reverse|rdns|static|broadband');

create or replace table banners_clean as
  select * replace (
      list_filter(kev_cves, lambda c: not list_contains({ambient}, c) or list_contains(verified_cves, c)) as kev_cves,
      list_filter(ransomware_cves, lambda c: not list_contains({ambient}, c) or list_contains(verified_cves, c)) as ransomware_cves),
    list_filter(kev_cves, lambda c: list_contains({ambient}, c)) as ambient_kevs
  from banners where entity not in (select entity from infra);

create or replace table companies as
with b as (
  select *,
    -- per-banner severity used to order the evidence a rep sees first
    (case when compromised or malicious then 100 else 0 end)
    + 40*(len(ransomware_cves)>0)::int + 30*(len(kev_cves)>0)::int + 25*db_no_auth::int
    + 15*(risky_service in {remote})::int + 10*ics::int + 8*eol::int + 6*ai_exposed::int
    + 35*(len(verified_cves)>0)::int + 5*edge_device::int + max_epss*10 + max_cvss as sev
  from banners_clean
)
select
  entity,
  any_value(entity_src) filter (where entity_src='cert')                    as cert_src,
  top_by_freq(list(entity_src), 1)[1]                                       as entity_src,
  count(*)                                                                  as banners,
  count(distinct ip)                                                        as ips,
  count(distinct port)                                                      as ports,
  count(distinct country)                                                   as countries,
  top_by_freq(list(country), 1)[1]                                          as country,
  top_by_freq(list(city), 1)[1]                                             as city,
  top_by_freq(list(org), 1)[1]                                              as hosting_org,
  bool_or(entity_src = 'whois_org')                                         as owns_netblock,
  top_by_freq(list(cert_org), 5)                                            as cert_orgs,
  top_by_freq(list(http_title), 8)                                          as titles,
  top_by_freq(flatten(list(tech)), 15)                                      as tech,
  top_by_freq(list(sec_contact), 1)[1]                                      as sec_contact,
  bool_or(securitytxt)                                                      as has_securitytxt,
  avg(case when http_status is not null then (waf is not null)::int end)    as waf_share,
  bool_or(compromised or malicious)                                         as s_compromised,
  bool_or(len(ransomware_cves) > 0)                                         as s_ransomware_cve,
  bool_or(edge_device and len(kev_cves) > 0)                                as s_kev_edge,
  bool_or(len(kev_cves) > 0)                                                as s_kev_cve,
  bool_or(len(verified_cves) > 0)                                           as s_verified_cve,
  bool_or(len(ambient_kevs) > 0)                                            as s_ambient_kev,
  list_reverse_sort(list_distinct(flatten(list(verified_cves))))            as verified_list,
  list_reverse_sort(list_distinct(flatten(list(ambient_kevs))))             as ambient_kev_list,
  bool_or(db_no_auth)                                                       as s_db_no_auth,
  bool_or(heartbleed)                                                       as s_heartbleed,
  bool_or(risky_service in {remote})                                        as s_remote_access,
  bool_or(ics)                                                              as s_ics,
  bool_or(max_epss >= 0.5)                                                  as s_high_epss,
  bool_or(db_open is not null)                                              as s_db_open,
  bool_or(eol)                                                              as s_eol,
  bool_or(ai_exposed)                                                       as s_ai_exposed,
  bool_or(edge_device)                                                      as s_edge_device,
  bool_or(open_dir)                                                         as s_open_dir,
  bool_or(ntlm_domain is not null)                                          as s_ntlm_leak,
  bool_or(cert_expired)                                                     as s_cert_expired,
  bool_or(weak_tls)                                                         as s_weak_tls,
  bool_or(cert_self_signed)                                                 as s_self_signed,
  coalesce(avg(case when http_status is not null then (waf is null)::int end) > 0.5, false) as s_no_waf,
  coalesce(avg(missing_sec_headers) >= 3, false)                            as s_missing_headers,
  -- timing
  min(cert_days_left) filter (where cert_days_left >= 0)                    as min_cert_days_left,
  bool_or(list_has_any(list_transform(kev_cves, lambda c: c[5:8]), ['2025','2026'])) as fresh_kev,
  bool_or(list_has_any(list_transform(top_cves, lambda c: c[5:8]), ['2026']))    as fresh_cve,
  list_reverse_sort(list_distinct(flatten(list(kev_cves))))                 as kev_list,
  list_reverse_sort(list_distinct(flatten(list(ransomware_cves))))          as ransomware_list,
  list_sort(list(distinct risky_service) filter (where risky_service is not null)) as remote_services,
  list_sort(list(distinct db_open) filter (where db_open is not null))      as databases,
  top_by_freq(list(ntlm_domain), 3)                                         as ntlm_domains,
  max(max_cvss)                                                             as max_cvss,
  max(max_epss)                                                             as max_epss,
  sum(n_cves)                                                               as total_cves,
  min(ts)                                                                   as first_seen,
  max(ts)                                                                   as last_seen,
  list(struct_pack(
        ip := regexp_replace(ip, '\\.\\d+\\.\\d+$', '.x.x'),  -- mask: a sales tool needs the company, not a target list
        port, product := coalesce(product, module), version, cves := top_cves[1:3],
        kev := kev_cves[1:3], flag := concat_ws(' ',
            case when compromised or malicious then 'COMPROMISED' end,
            case when len(ransomware_cves)>0 then 'RANSOMWARE-CVE' end,
            case when len(kev_cves)>0 then 'KEV' end,
            case when len(verified_cves)>0 then 'VERIFIED-CVE' end,
            case when db_no_auth then 'OPEN-DB' end,
            case when risky_service in {remote} then upper(risky_service) end,
            case when eol then 'EOL' end, case when ics then 'ICS' end,
            case when ai_exposed then 'AI' end, case when edge_device then 'EDGE' end,
            case when cert_expired then 'CERT-EXPIRED' end),
        title := http_title)
      order by sev desc, ip, port, ts, product, version)[1:8]               as evidence
from b
group by entity;
"""


# Most frequent values first, ties alphabetical. DuckDB aggregates in parallel, so a bare list()/mode()
# comes back in a different order each run; slicing that changed segment, Fit and score between runs.
TOP_BY_FREQ = """
create or replace macro top_by_freq(l, k) as list_transform(list_sort(list_transform(
  map_entries(list_aggregate(l, 'histogram')), lambda e: struct_pack(n := -(e.value::bigint), v := e.key))),
  lambda e: e.v)[1:k]
"""

def own_contact(entity: str, contact: str | None) -> str | None:
    """security.txt contact, only when it is on the company's own domain.

    Copied templates point at someone else (security@google.com on dozens of unrelated hosts), and a
    few are personal webmail addresses that should never be republished next to exposure data."""
    if not contact or entity.startswith("org:"):
        return None
    return contact if registrable(contact.rsplit("@", 1)[-1]) == entity else None


def need_score(row: dict) -> tuple[float, list[dict]]:
    raw, hits = 0.0, []
    for key, (pts, play) in SIGNALS.items():
        if row.get(f"s_{key}"):
            raw += pts
            hits.append({"signal": key, "points": pts, "play": play})
    # saturating: first big finding matters most, stacking more still helps but less
    return 100 * (1 - math.exp(-raw / 70)), hits


def fit_score(row: dict) -> tuple[float, list[str]]:
    why, s = [], 0.0
    ips = row["ips"] or 0
    s += min(math.log2(1 + ips) / 6, 1.0) * 0.40          # attack surface ~ org size; 63+ IPs maxes out
    if ips >= 10:
        why.append(f"{ips} internet-facing IPs")
    if row["owns_netblock"]:
        s += 0.20
        why.append("owns its IP space (enterprise network)")
    if row["cert_src"]:
        s += 0.15
        why.append("own TLS-certified domain")
    if row["cert_orgs"]:
        s += 0.10
        why.append(f"OV/EV cert as '{row['cert_orgs'][0]}'")
    if (row["countries"] or 0) > 1:
        s += 0.10
        why.append(f"present in {row['countries']} countries")
    if row["regulated"]:
        s += 0.10
        why.append(f"regulated sector ({row['segment']})")
    if row["has_securitytxt"]:
        s += 0.05
        why.append("publishes security.txt (has a security owner)")
    return min(s, 1.0), why


def timing(row: dict) -> tuple[float, list[str]]:
    mult, why = 1.0, []
    if row["fresh_kev"]:
        mult += 0.15
        why.append("exposed to a recently-weaponised CVE (2025-26 KEV)")
    elif row["fresh_cve"]:
        mult += 0.05
        why.append("running software with 2026 CVEs")
    d = row["min_cert_days_left"]
    if d is not None and d <= 21:
        mult += 0.05
        why.append(f"TLS cert expires in {d} days — infra work is happening now")
    if row["s_compromised"]:
        mult += 0.10
        why.append("indicators of compromise observed in this scan")
    return mult, why


def run(facts: str, out: str, top: int) -> None:
    os.makedirs(out, exist_ok=True)
    con = duckdb.connect(os.path.join(out, "scoring.duckdb"))
    con.execute("set preserve_insertion_order=false")
    con.execute(TOP_BY_FREQ)
    remote = "(" + ",".join(f"'{r}'" for r in REMOTE) + ")"
    con.execute(f"create or replace view raw as select * from read_parquet('{facts}/**/*.parquet', hive_partitioning=true)")
    ambient_rows = con.execute(
        f"select c, count(*) n from (select unnest(kev_cves) c from raw) group by c having n > {AMBIENT_KEV_BANNERS} order by n desc"
    ).fetchall()
    ambient = "[" + ",".join(f"'{c}'" for c, _ in ambient_rows) + "]::varchar[]"
    print("ambient KEVs:", ambient_rows)
    con.execute(AGG_SQL.format(facts=facts, remote=remote, ambient=ambient, cpe=CPE_PAT, generic=GENERIC_ORG))
    print(con.execute("select why, count(*) from infra group by why order by 2 desc").fetchall())
    n_infra = con.execute("select count(distinct entity) from infra").fetchone()[0]
    rows = con.execute("select * from companies").fetchall()
    cols = [c[0] for c in con.description]
    print(f"companies={len(rows):,} infra_namespaces_dropped={n_infra:,}")

    scored = []
    for r in rows:
        row = dict(zip(cols, r))
        seg, regulated, seg_why = classify(row["entity"].removeprefix("org:"), row["cert_orgs"], row["titles"])
        row.update(segment=seg, regulated=regulated, segment_reason=seg_why,
                   sec_contact=own_contact(row["entity"], row["sec_contact"]))
        need, hits = need_score(row)
        if need == 0:
            continue
        fit, fit_why = fit_score(row)
        mult, time_why = timing(row)
        score = min(100.0, need * (0.55 + 0.45 * fit) * mult)
        plays: dict[str, int] = {}
        for h in hits:
            plays[h["play"]] = plays.get(h["play"], 0) + h["points"]
        row.update(
            score=round(score, 1), need=round(need, 1), fit=round(fit * 100, 1), timing=round(mult, 2),
            signals=hits, fit_reasons=fit_why, timing_reasons=time_why,
            primary_play=max(plays, key=plays.get), plays=sorted(plays, key=plays.get, reverse=True),
            tier="Hot" if score >= 60 else "Warm" if score >= 35 else "Nurture",
            name=row["entity"].removeprefix("org:").title() if row["entity"].startswith("org:") else row["entity"],
        )
        scored.append(row)
    scored.sort(key=lambda r: (-r["score"], r["entity"]))  # entity breaks ties: same input, same ranking
    print(f"scored (need>0)={len(scored):,}  hot={sum(r['tier']=='Hot' for r in scored):,}")

    # Full scored table back to DuckDB/Parquet for analysis + evaluation.
    flat_keys = ["entity", "name", "score", "need", "fit", "timing", "tier", "primary_play", "segment",
                 "regulated", "country", "ips", "banners", "owns_netblock", "has_securitytxt",
                 "s_compromised"] + [f"s_{k}" for k in SIGNALS if k != "compromised"]
    with open(os.path.join(out, "scores.jsonl"), "w") as fh:
        for r in scored:
            fh.write(json.dumps({k: r[k] for k in flat_keys}) + "\n")

    keep = ["entity", "name", "score", "need", "fit", "timing", "tier", "primary_play", "plays", "segment",
            "regulated", "segment_reason", "country", "city", "countries", "ips", "ports", "banners",
            "owns_netblock", "hosting_org", "cert_orgs", "titles", "tech", "sec_contact", "has_securitytxt",
            "signals", "fit_reasons", "timing_reasons", "kev_list", "verified_list", "ambient_kev_list", "ransomware_list", "remote_services",
            "databases", "ntlm_domains", "max_cvss", "max_epss", "total_cves", "min_cert_days_left",
            "evidence", "entity_src"]
    app = [{k: r[k] for k in keep} for r in scored[:top]]
    for r in app:
        r["titles"] = (r["titles"] or [])[:3]
        r["evidence"] = (r["evidence"] or [])[:6]
        r["kev_list"] = (r["kev_list"] or [])[:10]

    # Campaign view: one KEV CVE -> every account exposed to it (how vendors run "patch-now" plays).
    campaigns: dict[str, list[str]] = {}
    for r in scored:
        for c in r["kev_list"] or []:
            campaigns.setdefault(c, []).append(r["entity"])
    camp = sorted(({"cve": c, "accounts": len(v), "ransomware": any(c in (x.get("ransomware_list") or [])
                    for x in scored[:top] if x["entity"] in set(v[:200])), "top": v[:200]}
                   for c, v in campaigns.items()), key=lambda x: (-x["accounts"], x["cve"]))[:60]

    stats = {
        "companies_resolved": len(rows), "companies_with_need": len(scored), "infra_dropped": n_infra,
        "banners_scanned": con.execute("select count(*) from raw").fetchone()[0],
        "banners": con.execute("select count(*) from banners").fetchone()[0],  # attributed to a company
        "tiers": {t: sum(r["tier"] == t for r in scored) for t in ("Hot", "Warm", "Nurture")},
        "plays": {p: sum(r["primary_play"] == p for r in scored) for p in sorted({r["primary_play"] for r in scored})},
        "scan_window": con.execute("select min(ts), max(ts) from banners").fetchone(),
        "ambient_kevs": ambient_rows,
    }
    with open(os.path.join(out, "app_data.json"), "w") as fh:
        json.dump({"accounts": app, "campaigns": camp, "stats": stats}, fh, default=str, separators=(",", ":"))
    print(json.dumps(stats, indent=1, default=str))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("facts")
    ap.add_argument("out")
    ap.add_argument("--top", type=int, default=6000)
    a = ap.parse_args()
    run(a.facts, a.out, a.top)
