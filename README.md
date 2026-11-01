# Exposure Radar: AI sales intelligence for a cybersecurity vendor

**Question:** of the thousands of businesses in the market, which ones need cybersecurity help *right now*, and what does a rep say on the first call?

**Answer:** read the internet the way an attacker does. The dataset is a one-day, internet-wide service scan: 14.6M banners, 123 GB of JSON, 17.6 GB zstd. Every banner describes one host:port, with CVE matches (CISA KEV and ransomware flags, EPSS), TLS certs, HTTP headers, NTLM handshakes and tags. Exposure Radar turns that into a ranked list of companies. Each account comes with the evidence behind it, a reason to call this week, and a suggested first touch.

* **Live app (public):** https://priyam21.github.io/exposure-radar/ (source in `app/`, static, no build step). Also on claude.ai: https://claude.ai/artifact/MmwnM6oE2tV1JUGU24WDnX. See *Hosting* below.
* **Offline replica of the live app:** [`report/exposure-radar-app.html`](report/exposure-radar-app.html) is the same interactive app (filters, account drawer, plays, campaigns, *How it works*) in one 12 MB file with the data inlined. It opens by double-click, needs no server or network, and is the drop-in replacement if the live link is unavailable. Every `run.py` run rebuilds it with `pipeline/bundle_app.py`; `app.js` is inlined unchanged.
* Pipeline: `pipeline/` (Python + DuckDB). Tests: `tests/`. Evaluation: `pipeline/evaluate.py`, `eval/`.

---

## 1. What is actually in the file (and the traps)

I profiled the raw data before writing any scoring code. Most of what the file seems to say at first glance is wrong, and these traps shaped every decision below:

| Looks like | Actually | What I did |
|---|---|---|
| 300k+ banners with a CISA **KEV** CVE | Matches are inferred from version strings. Only **70 of 245k** sampled CVE matches are `verified`. HTTP/2 Rapid Reset (CVE-2023-44487) alone matches 173k banners, and distros backport fixes without bumping versions. | CVEs matched on >1,000 banners are **ambient** and count only as low-weight hygiene, unless the scanner verified that host. The threshold comes from the data, not a hand-kept list. |
| `ransomware_campaign` is set on many CVEs | It is the **string** `"Known"`/`"Unknown"`, so a truthiness check flags every KEV as ransomware-linked. | Only `== "Known"` counts. There is a regression test for it. |
| facebook.com, Equifax and KeyBank are running njRAT / Remcos | `_shodan.module` names like `njrat78` or `darktrack-rat` are the **probe that was sent**, not a detection. | "Compromised" means a `c2`/`malware`/`compromised` tag or a fingerprinted C2 product only. Regression test included. |
| ~48k hosts expose VNC, ~38k WinRM, ~11k Kubernetes, ~8k Docker | Those were the default ports, but **98–99%** of those banners were an HTTP probe that identified no product. Same trap for perimeter devices: a `mikrotik-routeros` module is the probe sent, not a router found. | A service counts only when the product names it, or its own protocol parser answered and no other product did. Appliances are read from product, page title or WAF, never the module. Regression tests included. |
| 87% of banners have an `org` | It is the WHOIS owner of the netblock. That is usually a CDN (Incapsula answers on every port), a cloud, or an ISP whose *customers'* routers and cameras sit in the block. A naive first ranking was **entirely telcos** (MTN, Telia, Spark). | Entity resolution plus a data-driven infrastructure filter (§2). |
| Hostnames identify the company | `syn-173-197-170-173.biz.spectrum.com`, `host-202.dedicated.vsys.host` and `hosted-by.servereasy.it` are provider namespaces. | Hostname-shape and template-diversity tests (§2). |

**Hidden signals worth having:**

* **NTLM leaks the internal Active Directory domain** (`ntlm.dns_domain_name`). Companies leaking it show **17× lift** vs. observed compromise.
* **`security.txt`** gives a named security contact, so the rep has someone to reach out to.
* **OV/EV certificate subject `O=`** gives the legal entity name (e.g. *Thames Water Limited*, *Paramount Global*), which beats any guess from the domain.
* **Perimeter appliances** (Fortinet, Ivanti, Citrix NetScaler, SonicWall, Sophos, F5…) are the #1 initial-access vector, and here a CVE match is firmware-specific rather than a distro guess.
* **Exposed AI / MCP endpoints**: a brand-new attack surface that almost nobody's controls cover yet.
* **Certificate expiring in ≤21 days**: infrastructure work is happening now, which gives a "why this week" hook.

## 2. Who is the company? (entity resolution)

A scan is keyed by IP, but reps sell to companies. Each banner maps to a registrable domain (eTLD+1, offline PSL) in this order of trust: **TLS cert CN/SANs → HTTP Host → reverse DNS (only if not IP-shaped) → WHOIS org (only if not a hosting/telco)**. See `pipeline/entity.py`.

The blocklist of CDNs and clouds is only a seed. The important part is **data-driven** (`pipeline/score.py`, `infra` table), calibrated on known cases:

| Test | Enterprise | Provider | Rule |
|---|---|---|---|
| Consumer-device (CPE) share of the org's banners | ≤1% (KeyBank, Surescripts) | 8–42% (MTN, Spark, Telia) | org ≥ 8% → ISP |
| Other companies' certs on the org's IPs | ~1 | ≥10 (Cluster Logic 172, Shopify 533) | ≥10 → hosting |
| Hostname **templates per IP** | ≥0.43 (MIT 0.56, USP 0.84) | ≤0.11 (vsys.host 0.005, sl-reverse 0.014) | ≤0.15 → provider namespace |
| Seen across many unrelated networks | – | default/shared certs | ≥25 orgs → shared |

The filter removes 9,380 namespaces. Result: **361k companies** resolved from 2.05M attributable banners, and 302k of them have at least one need signal (301,859).

## 3. Scoring

`Score = Need × (0.55 + 0.45·Fit) × Timing`, capped at 100. Tiers: Hot ≥ 60, Warm ≥ 35.

* **Need (0–100):** a saturating sum `100·(1 − e^(−points/70))` over company-level signals. The first big finding matters most; stacking more still helps, but less. Points: compromise 40, ransomware-linked CVE 32, KEV on a perimeter device 30, verified CVE 28, open DB without auth 24, KEV 22, Heartbleed 18, exposed RDP/SMB/Telnet/VNC/WinRM 16, ICS 16, EPSS ≥ 0.5 12, then down to hygiene (expired cert, legacy TLS, no WAF…). Signals count once per company: one exposed RDP box is as good an opener as fifty.
* **Fit (0–1):** whether this is a real business worth calling. Inputs: attack-surface size (log IPs), owns its netblock, own TLS-certified domain, OV cert legal entity, multi-country, regulated sector (healthcare, finance, gov, edu, industrial), and a security owner (security.txt).
* **Timing (×1.0–1.3):** recently weaponised KEV (2025–26), cert expiring ≤21 days, live compromise.
* **Play:** each account gets the sales play with the most evidence behind it (Active compromise → IR/MDR, Exploited perimeter device → ASM/edge patching, Exposed data store → DSPM…). The app shows a talk track whose every sentence maps to a field in the evidence table.
* **Segment:** rule-based on domain TLD → cert org → page titles, with the matched keyword shown (`segment_reason`), so every label is traceable.

IPs are masked (`a.b.x.x`) in the app. The tool targets companies; it is not a target list.

## 4. Does it work? (`pipeline/evaluate.py` → `data/out/evaluation.json`)

There are no "will buy" labels in a scan, so each test hides a signal and checks whether the other signals still find those companies. Every test is compared against the naive rule "rank by footprint size".

| Test | n positives | Score AUC [95% CI] | Size-baseline AUC | Top-10% lift (score vs size) |
|---|---|---|---|---|
| Held-out **observed compromise** | 16 | **0.74** [0.60–0.88] | 0.64 [0.49–0.79] | 5.0× vs 3.1× |
| Held-out **scanner-verified vulnerability** (all CVE signals withheld) | 680 | **0.86** [0.84–0.88] | 0.57 [0.55–0.59] | 3.8× vs 2.2× |

* **Reliability (split-half):** each company is scored from two disjoint halves of its IPs. Spearman ρ = 0.62, tier agreement 94% (21k companies with ≥4 IPs). The score is a property of the company, not of which hosts happened to be scanned.
* **Precision audit of the top domain-identified accounts** (is this a real organisation, not an ISP/hoster?): **90% @10, 85% @20, 72% @50**. Labels are in `eval/precision_audit_top50.csv`, keyed by company and applied to the current ranking, so a rescore cannot reuse a stale order (`evaluate.py` lists any unlabelled newcomer). I (Claude, the coding agent) labelled them from the same evidence the app shows, so a human should spot-check them. The misses are ISP, telecom and hosting brands (free.fr, dattaweb.com, uzpak.uz). A spot-check of the top 25 WHOIS-org-only accounts found mostly small ISPs and hosters, which is why the app shows **domain-identified accounts by default**.
* **Signal lift table** (in the app's *How it works* tab) shows which signals co-occur with compromise: open DB without auth, ransomware CVE, verified CVE, exposed DB, NTLM leak, KEV, remote access. Hygiene-only signals (missing headers, no WAF) sit at ~1×, so they carry little weight. Weights were set by hand and checked against this table, **not fitted** to 16 labels.

Every data trap in §1 has a regression test (`tests/test_signals.py`, 10 tests).

## 5. Scale: hundreds to thousands of files per month

| Stage | What | Measured on this file (MacBook, 12 workers) |
|---|---|---|
| **Extract** (`extract.py`) | Streaming zstd → orjson → one compact fact row per banner → Parquet. Chunked multiprocessing; never holds the file in memory. | **14.6M banners in 190 s** (~77k/s), 2.4 GB peak RSS, 123 GB JSON → **665 MB Parquet** (0.5%) |
| **Score** (`score.py`) | DuckDB aggregation of facts → companies → scores → app JSON | ~25 s |
| **Evaluate** (`evaluate.py`) | Held-out tests, split-half, audit | ~4 s |
| **Orchestrate** (`run.py`) | Idempotent: a manifest skips files already extracted, then the window is rescored | — |

* **Map is embarrassingly parallel.** Each file is independent, so in production `extract.py` runs as one container job per file (S3 event → queue → job). Measured cost is ~12 CPU-minutes per file (726 s user+sys), so 1,000 files/month is ~200 CPU-hours/month, roughly $5–10 on spot instances. Extraction is decompress/parse-bound and scales linearly with cores.
* **Reduce reads only Parquet** (0.5% of raw size), so rescoring a 30-day window is one DuckDB/Spark aggregation, not a re-parse.
* **Next step for multi-day data:** add `first_seen` per (company, ip, port) so "new exposure since last week" becomes a timing signal. The schema already carries `ts` and `file_id` for this.

## 6. Key decisions

* **Deterministic scoring, no LLM at runtime.** It costs $0 per file, is reproducible, and every point is explainable to a rep. Reproducible is tested literally: two runs on the same input give byte-identical `app_data.json`, `evaluation.json` and offline replica. Every list is ranked by frequency with alphabetical ties, and every sort has a tie-breaker, because DuckDB aggregates in parallel and returns unordered lists in a different order each run. At thousands of files a month, an LLM per banner or per company would be the dominant cost and an unauditable source of error.
* **Where AI was used: the dev loop.** The whole repo was built with Claude Code (Opus 5.5) as the coding agent. How I kept it honest: (1) profile the raw data before scoring, which found the four traps in §1; (2) every trap becomes a regression test; (3) every rule is calibrated against named examples on both sides (the tables in §2); (4) the ranking is judged by held-out tests and a written audit, not by eye. The LLM-labelled audit is marked as such.
* **Company, not IP, is the unit.** Signals are booleans per company, so one rep conversation is backed by the single worst exposure, not by a host count that would just reward size.
* **Precision over recall at the top.** It is cheaper for sales to miss a prospect than to call an ISP about its customers' routers.
* **Static app.** Free to host anywhere, instant filtering over 6,000 accounts, CSV export for the CRM.

## Run it

All commands run from the repo root. Tested with Python 3.13. The scan file is zstd-compressed JSONL; any file name works, with or without a `.zst` extension.

### 0. Set up once

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Set the input path once per shell. Quote it: the assignment folder name ends in a space (`DQ_Assignment `).

```bash
SCAN="/path/to/DQ_Assignment /b2_download_file_by_id"
```

### Option A: one command

`run.py` does everything in order:

1. Extracts every new scan file.
2. Scores and evaluates.
3. Copies the results into `app/data/`.
4. Rebuilds the offline replica `report/exposure-radar-app.html`.

It records finished files in `data/manifest.json` and skips them next time, so a cron job or queue can call it blindly. Delete `data/manifest.json` to force a file to be extracted again.

```bash
.venv/bin/python -I pipeline/run.py "$SCAN" data
```

The first argument is a glob, so `"/landing/*.zst"` processes a whole month of files. Use `--app-dir` and `--replica` to write the app data and the replica somewhere else.

### Option B: step by step

| Step | Command | Output | Time on this file |
|---|---|---|---|
| 1. Extract | `.venv/bin/python -I pipeline/extract.py "$SCAN" data/facts` | `data/facts/file_id=<id>/*.parquet` | ~3 min (12 workers) |
| 2. Score | `.venv/bin/python -I pipeline/score.py data/facts data/out --top 6000` | `data/out/app_data.json`, `scores.jsonl`, `scoring.duckdb` | ~25 s |
| 3. Evaluate | `.venv/bin/python -I pipeline/evaluate.py data/out` | `data/out/evaluation.json` | ~4 s |
| 4. Publish data | `cp data/out/app_data.json data/out/evaluation.json app/data/` | `app/data/*.json` | instant |
| 5. Build offline replica | `.venv/bin/python -I pipeline/bundle_app.py app report/exposure-radar-app.html` | `report/exposure-radar-app.html` | ~1 s |

Before re-extracting the same file, move or delete its old `data/facts/file_id=<id>/` folder, otherwise old and new parts are mixed. Options for `extract.py`: `--workers N` (default: CPU count − 2) and `--limit N` (first N lines only, for a quick sample).

Steps 4 and 5 are what `run.py` does at the end. Run them by hand after steps 1–3, or after any change to `app/`, so the replica always matches the live app.

### View the app and run the tests

```bash
python3 -m http.server 8000 --directory app
```

Open http://localhost:8000. The offline replica `report/exposure-radar-app.html` opens directly in a browser, with no server.

```bash
.venv/bin/python -m pytest -q tests
```

## Hosting

`app/` is plain HTML/CSS/JS plus two JSON files, so any static host works.

* **Live:** https://claude.ai/artifact/MmwnM6oE2tV1JUGU24WDnX. Same code; CSV export copies to the clipboard there because that sandbox blocks file downloads.
* **Offline replica:** `report/exposure-radar-app.html`, rebuilt on every pipeline run. Send it as a file when the live link is unavailable.
* **Public site:** https://priyam21.github.io/exposure-radar/ serves the offline replica as `index.html` from the public repo `priyam21/exposure-radar`, so this code repo can stay private. To publish a new build after a pipeline run:
  ```bash
  cp report/exposure-radar-app.html ../exposure-radar-site/index.html
  git -C ../exposure-radar-site commit -am "Update app build" && git -C ../exposure-radar-site push
  ```
* **GitHub Pages from this repo:** `.github/workflows/pages.yml` deploys `app/` on every push to `main` once this repo is public (Settings → Pages → Source: GitHub Actions).
* **Security contacts** are shown only when the security.txt address is on the company's own domain. Copied templates (`security@google.com` on unrelated hosts) and personal webmail addresses are dropped, so the public page republishes no individual's email.

## Limitations

* One day of data, so there's no trend or "newly exposed" signal yet (see §5).
* Entity resolution is the hardest part: about 28% of the top 50 are still provider brands. The next fix is an ASN-level "provider" classifier trained on the infra rules above as weak labels.
* Segment classification is keyword-based. It is good on TLDs (.edu/.gov) and weaker on page titles.
* "Fit" has no firmographics (revenue, headcount). In production, join on domain to a firmographic source, which is exactly what Firmable has.
