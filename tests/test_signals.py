"""Regression tests for the data traps found while profiling the scan file."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pipeline"))

from entity import registrable, resolve_entity  # noqa: E402
from extract import GENERIC_HOST, to_row  # noqa: E402
from segments import classify  # noqa: E402


def banner(**kw):
    base = {"port": 443, "timestamp": "2026-10-26T00:00:00", "_shodan": {"module": "https"},
            "ip_str": "203.0.113.7", "hostnames": [], "domains": [], "org": "Acme Corp", "isp": "Big ISP",
            "location": {"country_code": "US"}, "data": ""}
    base.update(kw)
    return base


def test_rat_probe_module_is_not_a_detection():
    # Shodan's "njrat78" module is the probe it *sent*; facebook.com is not running a RAT.
    r = to_row(banner(_shodan={"module": "njrat78"}, hostnames=["edge.facebook.com"]), "f")
    assert r["malicious"] is False


def test_c2_tag_is_a_detection():
    assert to_row(banner(tags=["c2"], product="Sliver C2"), "f")["malicious"] is True


def test_ransomware_field_is_string_not_bool():
    v = {"CVE-1": {"cvss": 9.8, "epss": 0.9, "kev": True, "ransomware_campaign": "Unknown", "verified": False},
         "CVE-2": {"cvss": 9.8, "epss": 0.9, "kev": True, "ransomware_campaign": "Known", "verified": True}}
    r = to_row(banner(vulns=v), "f")
    assert r["ransomware_cves"] == ["CVE-2"]
    assert sorted(r["kev_cves"]) == ["CVE-1", "CVE-2"]
    assert r["verified_cves"] == ["CVE-2"]


def test_infra_and_isp_names_are_not_companies():
    assert registrable("107.154.36.223.ip.incapdns.net") is None
    assert registrable("ec2-1-2-3-4.compute-1.amazonaws.com") is None
    assert registrable("vpn.thameswater.co.uk") == "thameswater.co.uk"
    ent, src = resolve_entity(banner(org="Comcast Cable Communications", isp="Comcast"), None, [], None)
    assert ent is None
    ent, src = resolve_entity(banner(hostnames=["syn-173-197-170-173.biz.spectrum.com"], ip_str="173.197.170.173",
                                     org="Charter", isp="Charter"), None, [], None)
    assert ent is None


def test_cert_beats_rdns():
    ent, src = resolve_entity(banner(hostnames=["mail.other.com"]), "portal.acme-health.com", [], None)
    assert (ent, src) == ("acme-health.com", "cert")


def test_generic_host_shape():
    assert GENERIC_HOST.match("vps1234.vsys.host")
    assert not GENERIC_HOST.match("vpn.cdc.gov")


def test_segment_domain_beats_title():
    seg, regulated, _ = classify("ufl.edu", [], ["UF Health patient portal"])
    assert seg == "Education" and regulated


def test_port_alone_is_not_an_exposed_service():
    # 99% of "VNC" on 5900/5901 was an HTTP probe that identified nothing; no product, no service.
    for port in (5900, 5985, 6443, 2375, 3389):
        assert to_row(banner(port=port, _shodan={"module": "http-simple-new"}), "f")["risky_service"] is None
    # the RDP parser answered, but the product says another service took the port
    assert to_row(banner(port=3389, _shodan={"module": "rdp"}, product="OpenSSH"), "f")["risky_service"] is None


def test_confirmed_services_still_count():
    assert to_row(banner(port=3389, _shodan={"module": "rdp"}), "f")["risky_service"] == "rdp"
    assert to_row(banner(port=5901, _shodan={"module": "http-simple-new"}, product="RealVNC Enterprise"), "f")["risky_service"] == "vnc"
    assert to_row(banner(port=5985, _shodan={"module": "http-simple-new"}, product="WinRM"), "f")["risky_service"] == "winrm"
    assert to_row(banner(port=10250, _shodan={"module": "https-simple-new"}, product="Kubernetes"), "f")["risky_service"] == "kubernetes"


def test_edge_device_needs_the_banner_not_the_probe():
    # "mikrotik-routeros" is the probe Shodan sent, like the *-rat modules
    assert to_row(banner(port=8728, _shodan={"module": "mikrotik-routeros"}), "f")["edge_device"] is False
    assert to_row(banner(product="MikroTik RouterOS", _shodan={"module": "mikrotik-routeros"}), "f")["edge_device"] is True
    assert to_row(banner(http={"title": "FortiGate"}), "f")["edge_device"] is True
    # a Confluence login page is a web app, not a perimeter device
    assert to_row(banner(http={"title": "Log In - Confluence"}), "f")["edge_device"] is False


def test_security_contact_must_be_on_the_company_domain():
    from score import own_contact
    assert own_contact("acme.com", "security@acme.com") == "security@acme.com"
    assert own_contact("acme.com", "psirt@eu.acme.com") == "psirt@eu.acme.com"
    # copied security.txt template, and a personal webmail address
    assert own_contact("acme.com", "security@google.com") is None
    assert own_contact("free.fr", "someone@hotmail.com") is None
    assert own_contact("org:acme corp", "security@acme.com") is None
