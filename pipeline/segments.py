"""Rule-based industry segmentation from domain TLD, company name, cert org and page titles.

Deterministic on purpose: it runs on every company in every file at zero marginal cost, and every
label can be traced to the keyword that produced it (shown in the app as `segment_reason`).
"""
from __future__ import annotations

import re

# Order matters: first match wins. (segment, regulated?, pattern)
RULES: list[tuple[str, bool, re.Pattern]] = [
    ("Government", True, re.compile(
        r"\.gov(\.\w\w)?$|\.mil$|\.gouv\.|\.gob\.|\.go\.\w\w$|\bcity of\b|\bcounty\b|municipal|ministry|"
        r"\bdepartment of\b|\bstate of\b|government|gemeinde|stadt |council\b|police|prefecture", re.I)),
    ("Healthcare", True, re.compile(
        r"hospital|clinic|health|medical|medic|pharma|dental|dentist|patient|care\b|healthcare|"
        r"\bnhs\b|physician|surgery|radiology|dicom|pacs|laborator|biotech|krankenhaus|klinik", re.I)),
    ("Financial Services", True, re.compile(
        r"\bbank|banco|banque|credit union|financ|insurance|insur|invest|capital|securities|"
        r"\bfund|wealth|payment|fintech|loan|mortgage|trading|brokerage|asset management|\.bank$|"
        r"versicherung|sparkasse|accounting|tax\b", re.I)),
    ("Education", True, re.compile(
        r"\.edu(\.\w\w)?$|\.ac\.\w\w$|\.k12\.|universit|college|school|academy|campus|"
        r"institute of|educational|student|lms|moodle|schule|hochschule", re.I)),
    ("Legal & Professional", False, re.compile(
        r"\blaw\b|legal|attorney|lawyer|solicitor|notar|consult|advisory|cpa\b|audit", re.I)),
    ("Manufacturing & Industrial", True, re.compile(
        r"manufactur|industr|factory|automation|engineering|steel|chemical|plastics|machin|"
        r"logistics|freight|shipping|energy|utility|utilities|power|electric|water|oil|gas\b|mining|"
        r"scada|plc\b|bacnet|modbus|aviation|aerospace|automotive", re.I)),
    ("Retail & E-commerce", False, re.compile(
        r"shop|store|retail|commerce|boutique|fashion|apparel|market|grocery|supermarket|"
        r"magento|woocommerce|shopify|\.shop$|\.store$", re.I)),
    ("Hospitality & Travel", False, re.compile(
        r"hotel|resort|travel|tour|airline|restaurant|booking|hospitality|casino", re.I)),
    ("Media & Telecom", False, re.compile(
        r"media|news|radio|\btv\b|broadcast|publishing|telecom|magazine|studio|entertainment", re.I)),
    ("Technology & SaaS", False, re.compile(
        r"software|\bsaas\b|cloud|platform|\btech|digital|data|\bapi\b|\bdev\b|\.io$|\.ai$|\.dev$|"
        r"systems|solutions|labs\b|it services|cyber|security", re.I)),
]


def classify(entity: str, cert_orgs: list[str] | None, titles: list[str] | None) -> tuple[str, bool, str]:
    """Return (segment, regulated, evidence_snippet)."""
    fields = [("domain", entity or "")]
    fields += [("cert", o) for o in (cert_orgs or [])[:3] if o]
    fields += [("title", t) for t in (titles or [])[:5] if t]
    # field-major: the company's own domain (.edu, .gov) outranks a keyword in some page title
    for src, text in fields:
        for seg, regulated, pat in RULES:
            m = pat.search(text)
            if m:
                return seg, regulated, f"{src}: …{m.group(0)}… in '{text[:60]}'"
    return "Other / Unknown", False, ""
