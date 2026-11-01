"""Entity resolution: which *company* does a banner belong to?

The scan record is keyed by IP, but a salesperson sells to companies. We map each banner to a
registrable domain (eTLD+1) using, in order of trust:

  1. TLS certificate CN / SANs          (the company proved it owns the name)
  2. HTTP Host the scanner was served    (virtual host = the site's own name)
  3. Reverse-DNS hostnames               (only if not auto-generated "1-2-3-4.isp.net" style)
  4. WHOIS org of the netblock           (only if the org isn't a hosting/telco/cloud provider)

Anything that only resolves to a hosting/CDN/ISP namespace is left unattributed (entity=None):
those IPs are someone else's infrastructure and would pollute every ranking.
"""
from __future__ import annotations

import re

import tldextract

_extract = tldextract.TLDExtract(suffix_list_urls=())  # bundled PSL snapshot: offline + deterministic

# Infrastructure namespaces (cloud, CDN, hosting, residential ISPs, dynamic DNS). Seed list —
# stage 2 adds more data-driven (domains whose hostnames are mostly IP-patterned).
INFRA_DOMAINS = {
    "incapdns.net", "googleusercontent.com", "amazonaws.com", "cloudfront.net", "akamaitechnologies.com",
    "akamaiedge.net", "akamai.net", "cloudflare.net", "cloudflare.com", "cloudflaressl.com", "fastly.net",
    "azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "azure.com", "windows.net", "linodeusercontent.com",
    "linode.com", "vultrusercontent.com", "vultr.com", "your-server.de", "ovh.net", "ovh.com", "contaboserver.net",
    "digitalocean.com", "herokuapp.com", "flyio.net", "fly.dev", "scw.cloud", "secureserver.net",
    "unifiedlayer.com", "hwclouds-dns.com", "awsglobalaccelerator.com", "imperva.com", "kasserver.com",
    "bc.googleusercontent.com", "1e100.net", "google.com", "googlevideo.com", "vercel.app", "netlify.app",
    "github.io", "pages.dev", "workers.dev", "web.app", "firebaseapp.com", "myshopify.com", "wpengine.com",
    "wpenginepowered.com", "squarespace.com", "wixsite.com", "mystrikingly.com", "hostgator.com",
    "bluehost.com", "dreamhost.com", "hetzner.com", "hetzner.de", "ionos.com", "1and1.com", "strato.de",
    "aliyuncs.com", "alibabacloud.com", "tencentcloud.com", "myqcloud.com", "huaweicloud.com",
    "ddns.net", "no-ip.org", "no-ip.com", "dyndns.org", "duckdns.org", "synology.me", "myfritz.net",
    "tplinkdns.com", "dynu.net", "freeddns.org", "hopto.org", "zapto.org", "ngrok.io", "ngrok-free.app",
    "localhost", "local", "lan", "home", "example.com", "plex.direct", "pbiaas.com", "oraclecloud.com",
    "oraclevcn.com", "beget.tech", "timeweb.ru", "hostinger.com", "namecheap.com", "pythonanywhere.com",
    "render.com", "onrender.com", "railway.app", "azureedge.net", "edgekey.net", "edgesuite.net",
    "rackspace.net", "softlayer.com", "leaseweb.net", "choopa.net", "constant.com", "hostwindsdns.com",
    "colocrossing.com", "psychz.net", "sakura.ne.jp", "kagoya.net", "xserver.jp", "bitly.com",
}
INFRA_ORG = re.compile(
    r"amazon|google|microsoft|azure|cloudflare|akamai|incapsula|imperva|fastly|digitalocean|linode|akamai|"
    r"vultr|choopa|hetzner|ovh|contabo|scaleway|aliyun|alibaba|tencent|huawei|oracle|ionos|strato|hostinger|"
    r"godaddy|hostgator|unified layer|bluehost|leaseweb|rackspace|softlayer|ibm cloud|fly\.io|cogent|"
    r"telecom|telekom|communications|broadband|cable|wireless|mobile|cellular|internet|isp\b|network|"
    r"hosting|host\b|server|datacenter|data center|colo|cloud|vps|dedicated|telefonica|vodafone|orange|"
    r"verizon|comcast|charter|spectrum|at&t|centurylink|lumen|level 3|ntt|kddi|softbank|chinanet|"
    r"china (unicom|mobile|telecom)|korea telecom|chunghwa|hinet|vnpt|viettel|airtel|jio|reliance|"
    r"\bbt\b|sky uk|virgin|telstra|optus|rogers|bell canada|shaw|telus|private customer|end user|ip pools|"
    r"meteverse|aceville|^ace$|reserved|unknown|residential|dsl|fiber|fibre|tele|netcom|pte\.? ?ltd|"
    r"customer|subscriber|pool|dynamic|static ip|so-net|services? provider|backbone|transit|exchange point",
    re.I)
GENERIC_CERT = re.compile(
    r"^(localhost|.*\.local|.*\.lan|.*\.home|.*\.internal|.*\.localdomain|default|example\.\w+|"
    r"plesk|acme|.*\.invalid|router|.*\.arpa)$", re.I)
IP_LIKE = re.compile(r"(\d{1,3}[.\-_x]){3}\d{1,3}")


def registrable(host: str | None) -> str | None:
    if not host:
        return None
    host = host.strip().lower().lstrip("*.").rstrip(".")
    if not host or IP_LIKE.search(host) or GENERIC_CERT.match(host):
        return None
    ext = _extract(host)
    if not ext.suffix or not ext.domain:
        return None
    rd = f"{ext.domain}.{ext.suffix}"
    if rd in INFRA_DOMAINS:
        return None
    return rd


def _rdns_generated(hostname: str, ip: str | None) -> bool:
    """True for ISP-generated reverse DNS like 'syn-173-197-170-173.biz.spectrum.com'."""
    if IP_LIKE.search(hostname):
        return True
    if ip and "." in ip:
        octets = ip.split(".")
        hits = sum(1 for o in octets if re.search(rf"(?<!\d){o}(?!\d)", hostname))
        if hits >= 3:
            return True
    return sum(c.isdigit() for c in hostname.split(".")[0]) >= 6


def normalize_org(org: str) -> str:
    o = re.sub(r"[,.]", " ", org.lower())
    o = re.sub(r"\b(inc|llc|ltd|limited|corp|corporation|co|gmbh|ag|sa|sas|bv|plc|pty|s\.?a|srl|spa|kk)\b", " ", o)
    return re.sub(r"\s+", " ", o).strip()


def resolve_entity(d: dict, cert_cn: str | None, sans: list[str], http_host: str | None):
    for name in [cert_cn, *sans[:5]]:
        rd = registrable(name)
        if rd:
            return rd, "cert"
    rd = registrable(http_host)
    if rd:
        return rd, "http_host"
    ip = d.get("ip_str")
    for h in d.get("hostnames") or []:
        if not _rdns_generated(h, ip):
            rd = registrable(h)
            if rd:
                return rd, "rdns"
    org, isp = d.get("org") or "", d.get("isp") or ""
    if org and org != isp and not INFRA_ORG.search(org):
        n = normalize_org(org)
        if len(n) >= 3:
            return f"org:{n}", "whois_org"
    return None, None
