"""Stage 1 — stream a zstd JSONL scan file into compact per-banner fact rows (Parquet).

One raw file (~17 GB zstd, ~100+ GB JSON) becomes a few hundred MB of Parquet holding only
the fields that matter for scoring. Each input file is processed independently, so a month of
files is an embarrassingly-parallel map over files (and over chunks inside each file).

Usage:
    python -I pipeline/extract.py <input.zst> <out_dir> [--workers N] [--limit N]
"""
from __future__ import annotations

import argparse
import hashlib
import io
import multiprocessing as mp
import os
import re
import sys
import time
from pathlib import Path

import orjson
import pyarrow as pa
import pyarrow.parquet as pq
import zstandard

sys.path.insert(0, str(Path(__file__).resolve().parent))
from entity import registrable, resolve_entity  # noqa: E402

CHUNK_LINES = 20_000

# Services that should never face the internet for a normal business: (product pattern, parser modules).
# A port alone is not evidence: 99% of "VNC" on 5900/5901 was an HTTP probe that identified nothing.
# A service counts when the product names it, or its own protocol parser ran and no other product answered.
RISKY_SERVICES = {
    "rdp": (r"remote desktop protocol|\brdp\b|xrdp|terminal serv", ("rdp", "rdpeudp")),
    "vnc": (r"vnc|\brfb\b", ("vnc",)),
    "smb": (r"samba|\bsmb", ("smb",)),
    "telnet": (r"telnet", ("telnet",)),
    "winrm": (r"winrm", ("winrm",)),
    "docker": (r"docker", ("docker",)),
    "kubernetes": (r"kubernetes|kubelet", ("kubernetes", "kubelet")),
    "netbios": (r"netbios", ("netbios",)),
    "ftp": (r"ftp", ("ftp",)),
    "snmp": (r"snmp", ("snmp",)),
    "ldap": (r"ldap|active directory", ("ldap",)),
    "mssql": (r"sql server|mssql", ("mssql",)),
    "mysql": (r"mysql|mariadb", ("mysql",)),
    "postgres": (r"postgres", ("postgres", "postgresql")),
    "redis": (r"redis", ("redis",)),
    "mongodb": (r"mongo", ("mongodb",)),
    "elastic": (r"elastic", ("elastic", "elasticsearch")),
    "memcached": (r"memcache", ("memcache", "memcached")),
    "rsync": (r"rsync", ("rsync",)),
}
RISKY_PAT = {name: re.compile(pat, re.I) for name, (pat, _) in RISKY_SERVICES.items()}
DB_KEYS = ("mysql", "mongodb", "redis", "elastic", "postgres", "mssql", "clickhouse", "couchdb",
           "influxdb", "memcached", "cassandra", "milvus")
# Perimeter appliances: the most-exploited class of device (VPNs/firewalls/ADCs/remote-access gateways).
# Web apps such as Confluence or Exchange are not perimeter devices; their KEVs still score as kev_cve.
EDGE_PAT = re.compile(
    r"fortinet|fortigate|fortios|sonicwall|pulse secure|ivanti|citrix|netscaler|palo alto|globalprotect|"
    r"checkpoint|check point|f5 big-?ip|bigip|cisco asa|anyconnect|sophos|watchguard|barracuda|zyxel|"
    r"draytek|mikrotik|juniper|vmware horizon",
    re.I)
C2_PAT = re.compile(r"\bc2\b|cobalt ?strike|sliver|metasploit|havoc|mythic|brute ratel|covenant|"
                    r"\brat\b|njrat|asyncrat|quasar|remcos|nanocore|darkcomet", re.I)
# Machine-numbered hostnames (vps1234., srv-56., s12345., static-x.) = a provider naming rented boxes;
# organisations name hosts by function (vpn., mail., lab.cs.).
GENERIC_HOST = re.compile(r"^(?:[a-z]{0,8}[-_]?\d{2,}[a-z0-9-]*|(?:vps|srv|server|host|static|dyn|node|cust|client|"
                          r"pool|ip|vm|vds|dedi|cloud|res|cpe|dsl|ppp|user)[-_.\d][^.]*)\.", re.I)
SAN_PAT = re.compile(rb"\x82.([a-z0-9*][a-z0-9.\-*]{2,250})", re.I | re.S)
EMAIL_PAT = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
SEC_HEADERS = ("strict-transport-security", "content-security-policy", "x-frame-options",
               "x-content-type-options")

SCHEMA = pa.schema([
    ("file_id", pa.string()), ("ts", pa.string()), ("ip", pa.string()), ("port", pa.int32()),
    ("module", pa.string()), ("product", pa.string()), ("version", pa.string()),
    ("org", pa.string()), ("isp", pa.string()), ("asn", pa.string()),
    ("country", pa.string()), ("city", pa.string()), ("cloud", pa.string()),
    ("entity", pa.string()), ("entity_src", pa.string()), ("domains", pa.list_(pa.string())),
    ("hostname", pa.string()), ("generic_host", pa.bool_()),
    ("tags", pa.list_(pa.string())),
    ("n_cves", pa.int32()), ("max_cvss", pa.float32()), ("max_epss", pa.float32()),
    ("kev_cves", pa.list_(pa.string())), ("ransomware_cves", pa.list_(pa.string())),
    ("top_cves", pa.list_(pa.string())), ("verified_cves", pa.list_(pa.string())),
    ("risky_service", pa.string()), ("db_open", pa.string()), ("db_no_auth", pa.bool_()),
    ("edge_device", pa.bool_()), ("eol", pa.bool_()), ("compromised", pa.bool_()),
    ("malicious", pa.bool_()), ("honeypot", pa.bool_()), ("open_dir", pa.bool_()),
    ("ics", pa.bool_()), ("ai_exposed", pa.bool_()), ("heartbleed", pa.bool_()),
    ("cert_expired", pa.bool_()), ("cert_self_signed", pa.bool_()), ("cert_days_left", pa.int32()),
    ("weak_tls", pa.bool_()), ("cert_org", pa.string()),
    ("http_title", pa.string()), ("http_status", pa.int32()), ("waf", pa.string()),
    ("missing_sec_headers", pa.int8()), ("securitytxt", pa.bool_()), ("sec_contact", pa.string()),
    ("ntlm_domain", pa.string()), ("tech", pa.list_(pa.string())), ("evidence", pa.string()),
])


def _cert_days_left(expires: str | None, ts: str) -> int | None:
    # cert dates look like 20261217172026Z; ts like 2026-10-26T11:59:52
    if not expires or len(expires) < 8:
        return None
    try:
        from datetime import date
        e = date(int(expires[:4]), int(expires[4:6]), int(expires[6:8]))
        t = date(int(ts[:4]), int(ts[5:7]), int(ts[8:10]))
        return (e - t).days
    except ValueError:
        return None


def entity_hint(h: str) -> bool:
    return registrable(h) is not None


def risky_service(module: str, product: str | None) -> str | None:
    """Confirmed exposed service, or None. Never from the port number alone."""
    if product:
        return next((name for name, pat in RISKY_PAT.items() if pat.search(product)), None)
    return next((name for name, (_, mods) in RISKY_SERVICES.items() if module in mods), None)


def is_edge(product: str | None, title: str | None, waf: str | None, d: dict) -> bool:
    """Perimeter appliance named by the banner itself, never by the probe module that was sent."""
    text = f"{product or ''} {title or ''} {waf or ''}"
    return bool(EDGE_PAT.search(text)) or any(k in d for k in ("fortinet", "sonicwall", "checkpoint"))


def to_row(d: dict, file_id: str) -> dict | None:
    port = d.get("port") or 0
    ts = d.get("timestamp") or ""
    sh = d.get("_shodan") or {}
    module = sh.get("module") or ""
    tags = d.get("tags") or []
    loc = d.get("location") or {}
    product = d.get("product")
    data = d.get("data") or ""

    # CVEs: keep only aggregates + the handful that matter for a talk track.
    vulns = d.get("vulns") or {}
    kev, ransom, verified, scored = [], [], [], []
    max_cvss = max_epss = 0.0
    for cve, v in vulns.items():
        cvss = v.get("cvss") or 0.0
        epss = v.get("epss") or 0.0
        max_cvss, max_epss = max(max_cvss, cvss), max(max_epss, epss)
        if v.get("kev") is True:
            kev.append(cve)
        if v.get("ransomware_campaign") == "Known":  # field is "Known"/"Unknown", not a bool
            ransom.append(cve)
        if v.get("verified") is True:  # actively confirmed, vs. inferred from a version banner
            verified.append(cve)
        scored.append((epss, cvss, cve))
    scored.sort(reverse=True)

    ssl = d.get("ssl") or {}
    cert = ssl.get("cert") or {}
    subj, iss = cert.get("subject") or {}, cert.get("issuer") or {}
    sans: list[str] = []
    for ext in cert.get("extensions") or []:
        if ext.get("name") == "subjectAltName":
            raw = (ext.get("data") or "").encode("latin-1", "ignore").decode("unicode_escape", "ignore")
            sans = [m.decode("ascii", "ignore") for m in SAN_PAT.findall(raw.encode("latin-1", "ignore"))]
            break
    versions = ssl.get("versions") or []
    weak_tls = any(v in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2") for v in versions)

    http = d.get("http") or {}
    headers = {k.lower() for k in (http.get("headers") or {})}
    sec_txt = http.get("securitytxt") or ""
    contact = None
    if sec_txt:
        m = EMAIL_PAT.search(sec_txt)
        contact = m.group(0) if m else None

    hostname = next((h for h in d.get("hostnames") or [] if entity_hint(h)), None)
    entity, entity_src = resolve_entity(d, cert_cn=subj.get("CN"), sans=sans, http_host=http.get("host"))

    risky = risky_service(module, product)
    db_open = next((k for k in DB_KEYS if k in d), None) or ("database" if "database" in tags else None)
    db_no_auth = bool(db_open) and bool(re.search(r"Total Size|Databases:|Total Docs|keyspace|db\d+:keys", data))

    edge = is_edge(product, http.get("title"), http.get("waf"), d)

    ntlm = d.get("ntlm") or {}
    comps = list((http.get("components") or {}).keys())[:12]
    hb = (d.get("opts") or {}).get("heartbleed") or ""

    evidence = f"{d.get('ip_str') or ''}:{port} {product or module} {d.get('version') or ''}".strip()
    if scored:
        evidence += " | " + ",".join(c for _, _, c in scored[:3])

    return {
        "file_id": file_id, "ts": ts, "ip": d.get("ip_str") or str(d.get("ipv6") or ""),
        "port": port, "module": module, "product": product, "version": d.get("version"),
        "org": d.get("org"), "isp": d.get("isp"), "asn": d.get("asn"),
        "country": loc.get("country_code"), "city": loc.get("city"),
        "cloud": (d.get("cloud") or {}).get("provider"),
        "entity": entity, "entity_src": entity_src, "domains": d.get("domains") or [], "tags": tags,
        "hostname": hostname, "generic_host": bool(hostname) and bool(GENERIC_HOST.match(hostname)),
        "n_cves": len(vulns), "max_cvss": max_cvss, "max_epss": max_epss,
        "kev_cves": kev, "ransomware_cves": ransom, "top_cves": [c for _, _, c in scored[:5]],
        "verified_cves": verified,
        "risky_service": risky, "db_open": db_open, "db_no_auth": db_no_auth,
        "edge_device": edge, "eol": "eol-product" in tags or "eol-os" in tags,
        "compromised": "compromised" in tags,
        # NB: modules like "njrat78"/"darktrack-rat" are the *probe* Shodan sent, not a detection —
        # only tags or a fingerprinted C2 product count as malicious.
        "malicious": "c2" in tags or "malware" in tags or bool(C2_PAT.search(product or "")),
        "honeypot": "honeypot" in tags, "open_dir": "open-dir" in tags or "open_dir" in d,
        "ics": "ics" in tags, "ai_exposed": "ai" in tags or "mcp" in tags or "mcp" in d,
        "heartbleed": "VULNERABLE" in hb,
        "cert_expired": bool(cert.get("expired")),
        "cert_self_signed": bool(cert) and (subj == iss or "self-signed" in tags),
        "cert_days_left": _cert_days_left(cert.get("expires"), ts) if cert else None,
        "weak_tls": weak_tls, "cert_org": subj.get("O"),
        "http_title": (http.get("title") or "")[:160] or None, "http_status": http.get("status"),
        "waf": http.get("waf"),
        "missing_sec_headers": sum(1 for h in SEC_HEADERS if h not in headers) if http else None,
        "securitytxt": bool(sec_txt), "sec_contact": contact,
        "ntlm_domain": ntlm.get("dns_domain_name") or ntlm.get("netbios_domain_name"),
        "tech": comps, "evidence": evidence[:300],
    }


def process_chunk(args: tuple[list[bytes], str, str, int]) -> tuple[int, int]:
    lines, file_id, out_dir, idx = args
    rows, bad = [], 0
    for line in lines:
        try:
            r = to_row(orjson.loads(line), file_id)
        except Exception:  # malformed banner — count it, never kill the chunk
            bad += 1
            continue
        if r:
            rows.append(r)
    if rows:
        tbl = pa.Table.from_pylist(rows, schema=SCHEMA)
        pq.write_table(tbl, os.path.join(out_dir, f"part-{idx:06d}.parquet"), compression="zstd")
    return len(rows), bad


def iter_chunks(path: str, limit: int | None):
    dctx = zstandard.ZstdDecompressor(max_window_size=2**31)
    with open(path, "rb") as fh, dctx.stream_reader(fh, read_size=1 << 24) as reader:
        buf, n = [], 0
        for line in io.BufferedReader(reader, buffer_size=1 << 24):
            buf.append(line)
            n += 1
            if len(buf) >= CHUNK_LINES:
                yield buf
                buf = []
            if limit and n >= limit:
                break
        if buf:
            yield buf


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("out_dir")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 2))
    ap.add_argument("--limit", type=int, default=None)
    a = ap.parse_args()

    file_id = hashlib.sha1(os.path.abspath(a.input).encode()).hexdigest()[:12]
    out_dir = os.path.join(a.out_dir, f"file_id={file_id}")
    os.makedirs(out_dir, exist_ok=True)
    t0, total, bad = time.time(), 0, 0
    with mp.Pool(a.workers) as pool:
        jobs = ((c, file_id, out_dir, i) for i, c in enumerate(iter_chunks(a.input, a.limit)))
        for i, (n, b) in enumerate(pool.imap_unordered(process_chunk, jobs, chunksize=1)):
            total, bad = total + n, bad + b
            if i % 50 == 0:
                print(f"[{time.time()-t0:7.0f}s] chunks={i} rows={total:,} bad={bad} "
                      f"rate={total/max(time.time()-t0,1):,.0f}/s", flush=True)
    print(f"DONE file_id={file_id} rows={total:,} bad={bad} secs={time.time()-t0:.0f}", flush=True)


if __name__ == "__main__":
    main()
