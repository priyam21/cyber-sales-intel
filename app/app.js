// Exposure Radar — static client. Loads the scored dataset produced by pipeline/score.py.
const PAGE = 100;
const state = { data: null, filtered: [], shown: PAGE, cve: "" };
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = (n) => Number(n).toLocaleString();

const SIGNAL_LABEL = {
  compromised: "Indicators of compromise on own asset",
  ransomware_cve: "CVE used in known ransomware campaigns",
  kev_edge: "Known-exploited CVE on VPN / firewall / edge device",
  verified_cve: "Vulnerability actively confirmed by the scanner",
  kev_cve: "CISA known-exploited vulnerability (KEV)",
  db_no_auth: "Database exposed without authentication",
  heartbleed: "Heartbleed-vulnerable TLS",
  remote_access: "Remote admin exposed (RDP / SMB / Telnet / VNC / WinRM)",
  ics: "Industrial control system exposed",
  high_epss: "CVE with ≥50% exploit probability (EPSS)",
  db_open: "Database port exposed to the internet",
  eol: "End-of-life product / OS",
  ai_exposed: "AI / MCP service exposed",
  edge_device: "Perimeter appliance exposed",
  open_dir: "Open directory listing",
  ntlm_leak: "NTLM leaks internal AD domain",
  cert_expired: "Expired TLS certificate",
  weak_tls: "Legacy TLS 1.0/1.1 or SSL enabled",
  self_signed: "Self-signed certificate",
  no_waf: "Web apps without a WAF",
  ambient_kev: "Unpatched web stack (version-inferred KEV)",
  missing_headers: "Missing HTTP security headers",
};

// First-touch talk tracks per play: what to say and what to sell. Deliberately templated (no LLM):
// every sentence is backed by a field in the evidence table below it.
const PLAYS = {
  "Active compromise": { pitch: "Incident response / MDR", open: (a) => `Our telemetry shows indicators of compromise on infrastructure tied to ${a.name}. This usually means an attacker already has a foothold — we can help you contain it this week.` },
  "Ransomware-linked vulnerability": { pitch: "Vulnerability management + ransomware readiness", open: (a) => `${a.name} has internet-facing systems exposed to ${(a.ransomware_list || [])[0] || "a CVE"}, which ransomware crews are actively using. Most victims are hit within weeks of exposure.` },
  "Exploited perimeter device": { pitch: "Attack-surface management / edge patching", open: (a) => `Your perimeter (VPN / firewall) is the #1 initial-access vector right now, and ${a.name} runs a device with ${(a.kev_list || [])[0] || "known exploited flaws"}.` },
  "Known-exploited vulnerability": { pitch: "Vulnerability management", open: (a) => `${a.name} has ${a.kev_list?.length || "several"} internet-facing issue(s) on CISA's known-exploited list${a.kev_list?.length ? ` (e.g. ${a.kev_list[0]})` : ""}. Happy to share the full list privately.` },
  "Exposed data store": { pitch: "Cloud / data security posture (CSPM/DSPM)", open: (a) => `We found ${(a.databases || []).join(", ") || "a database"} at ${a.name} reachable from the internet — the most common cause of silent data leaks.` },
  "Exposed remote access": { pitch: "Zero-trust access / MDR", open: (a) => `${a.name} exposes ${(a.remote_services || []).map((s) => s.toUpperCase()).join(", ")} directly to the internet. That is how most ransomware intrusions start.` },
  "OT / ICS exposure": { pitch: "OT security", open: (a) => `Industrial control interfaces at ${a.name} are reachable from the public internet — a regulator and insurer red flag.` },
  "AI / MCP exposure": { pitch: "AI security posture", open: (a) => `${a.name} has AI/MCP services exposed publicly. These new endpoints rarely sit behind the same controls as the rest of the estate.` },
  "End-of-life infrastructure": { pitch: "Vulnerability management / modernisation", open: (a) => `Parts of ${a.name}'s internet-facing estate run end-of-life software that will never be patched again.` },
  "Security hygiene gaps": { pitch: "Attack-surface management / compliance", open: (a) => `A quick outside-in review of ${a.name} shows hygiene gaps (expired certs, legacy TLS, missing headers) that auditors and cyber insurers check first.` },
};

async function load() {
  const [data, evaluation] = await Promise.all([
    fetch("data/app_data.json").then((r) => r.json()),
    fetch("data/evaluation.json").then((r) => (r.ok ? r.json() : null)).catch(() => null),
  ]);
  state.data = data;
  state.evaluation = evaluation;
  data.accounts.forEach((a, i) => {
    a.rank = i + 1;
    a._q = [a.name, a.entity, a.segment, a.country, a.hosting_org, ...(a.kev_list || []), ...(a.tech || []),
      ...(a.evidence || []).map((e) => `${e.product} ${e.version || ""} ${(e.cves || []).join(" ")}`)].join(" ").toLowerCase();
  });
  fillSelect("#f-play", count(data.accounts, (a) => a.primary_play));
  fillSelect("#f-seg", count(data.accounts, (a) => a.segment));
  fillSelect("#f-country", count(data.accounts, (a) => a.country || "—"));
  renderKpis();
  renderPlays();
  renderMethod();
  bind();
  apply();
}

function count(arr, key) {
  const m = new Map();
  arr.forEach((a) => m.set(key(a), (m.get(key(a)) || 0) + 1));
  return [...m.entries()].sort((a, b) => b[1] - a[1]);
}
function fillSelect(sel, entries) {
  const el = $(sel);
  entries.forEach(([k, n]) => el.insertAdjacentHTML("beforeend", `<option value="${esc(k)}">${esc(k)} (${fmt(n)})</option>`));
}

function renderKpis() {
  const s = state.data.stats;
  const k = [
    [fmt(s.banners_scanned ?? s.banners), s.banners_scanned ? "service banners analysed" : "banners matched to a company"],
    ...(s.banners_scanned ? [[fmt(s.banners), "matched to a company"]] : []),
    [fmt(s.companies_resolved), "companies identified"],
    [fmt(s.companies_with_need), "with a security need"],
    [fmt(s.tiers.Hot), "Hot accounts"],
    [fmt(s.tiers.Warm), "Warm accounts"],
    [`${String(s.scan_window[0]).slice(5, 10)} → ${String(s.scan_window[1]).slice(5, 10)}`, `scan window (${String(s.scan_window[0]).slice(0, 4)})`],
  ];
  $("#kpis").innerHTML = k.map(([b, t]) => `<div class="kpi"><b>${esc(b)}</b><span>${esc(t)}</span></div>`).join("");
}

function filters() {
  return {
    q: $("#q").value.trim().toLowerCase(), tier: $("#f-tier").value, play: $("#f-play").value,
    seg: $("#f-seg").value, country: $("#f-country").value, ips: +$("#f-ips").value || 1,
    reg: $("#f-reg").checked, contact: $("#f-contact").checked, own: $("#f-own").checked, named: $("#f-named").checked,
  };
}

function apply() {
  const f = filters();
  const terms = f.q.split(/\s+/).filter(Boolean);
  state.filtered = state.data.accounts.filter((a) =>
    (!f.tier || a.tier === f.tier) && (!f.play || a.plays.includes(f.play)) && (!f.seg || a.segment === f.seg) &&
    (!f.country || (a.country || "—") === f.country) && a.ips >= f.ips && (!f.reg || a.regulated) &&
    (!f.contact || a.sec_contact) && (!f.own || a.owns_netblock) && (!f.named || !a.entity.startsWith("org:")) &&
    terms.every((t) => a._q.includes(t)));
  state.shown = PAGE;
  renderRows();
}

function flags(a) {
  const seen = new Set();
  (a.evidence || []).forEach((e) => (e.flag || "").split(" ").filter(Boolean).forEach((x) => seen.add(x)));
  const crit = new Set(["COMPROMISED", "RANSOMWARE-CVE", "KEV", "OPEN-DB", "VERIFIED-CVE", "RDP", "SMB", "TELNET", "VNC"]);
  return [...seen].slice(0, 5).map((x) => `<span class="flag ${crit.has(x) ? "crit" : ""}">${esc(x)}</span>`).join("");
}

function renderRows() {
  const rows = state.filtered.slice(0, state.shown);
  $("#rows").innerHTML = rows.map((a, i) => `
    <tr data-e="${esc(a.entity)}">
      <td class="muted">${i + 1}</td>
      <td class="co"><b>${esc(a.name)}</b><small>${esc(a.city || "")}${a.sec_contact ? " · ✉ security contact" : ""}</small></td>
      <td class="num"><div class="score">${a.score.toFixed(0)}<div class="bar"><i style="width:${a.score}%"></i></div></div></td>
      <td><span class="pill ${a.tier}">${a.tier}</span></td>
      <td>${esc(a.primary_play)}<div>${flags(a)}</div></td>
      <td>${esc(a.segment)}</td>
      <td>${esc(a.country || "—")}</td>
      <td class="num">${fmt(a.ips)}</td>
    </tr>`).join("");
  $("#count").textContent = `${fmt(state.filtered.length)} accounts match`;
  $("#more").style.display = state.filtered.length > state.shown ? "block" : "none";
}

function openDetail(entity) {
  const a = state.data.accounts.find((x) => x.entity === entity);
  if (!a) return;
  const play = PLAYS[a.primary_play] || { pitch: "", open: () => "" };
  const sigs = (a.signals || []).slice().sort((x, y) => y.points - x.points);
  // the list is numbered within the current filter; the overall rank counts every account
  const viewRank = state.filtered.indexOf(a) + 1;
  const rankText = viewRank && viewRank !== a.rank ? `#${viewRank} in this view (#${a.rank} overall)` : `rank #${a.rank}`;
  $("#detail").innerHTML = `
    <h2>${esc(a.name)}</h2>
    <div class="muted">${esc(a.segment)}${a.regulated ? " (regulated)" : ""} · ${esc([a.city, a.country].filter(Boolean).join(", ") || "location unknown")} · ${rankText}</div>
    <div style="margin-top:8px"><span class="pill ${a.tier}">${a.tier}</span> <b style="font-size:18px;margin-left:6px">${a.score.toFixed(0)}</b><span class="muted"> / 100</span></div>
    <div class="breakdown">
      <div><b>${a.need.toFixed(0)}</b><span>Need — severity of exposure</span></div>
      <div><b>${a.fit.toFixed(0)}</b><span>Fit — size &amp; reachability</span></div>
      <div><b>×${a.timing.toFixed(2)}</b><span>Timing — why now</span></div>
    </div>

    <h4>Suggested first touch · ${esc(play.pitch)}</h4>
    <div class="talk"><p>${esc(play.open(a))}</p>
      <p class="muted" style="margin:0">Contact: ${a.sec_contact ? `<b>${esc(a.sec_contact)}</b> (from security.txt)` : "no published security contact. Target the CISO / IT director"}</p></div>

    ${a.timing_reasons?.length ? `<h4>Why now</h4><ul class="plain">${a.timing_reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>` : ""}

    <h4>Need signals</h4>
    ${sigs.map((s) => `<div class="sig"><span>${esc(SIGNAL_LABEL[s.signal] || s.signal)}</span><span class="muted">+${s.points}</span></div>`).join("")}

    <h4>Fit</h4>
    <ul class="plain">${(a.fit_reasons || []).map((r) => `<li>${esc(r)}</li>`).join("") || "<li class='muted'>small footprint</li>"}</ul>
    ${a.segment_reason ? `<p class="muted" style="font-size:12px">Segment from ${esc(a.segment_reason)}</p>` : ""}

    <h4>Evidence (most severe first)</h4>
    <table class="ev">${(a.evidence || []).map((e) => `
      <tr><td><code>${esc(e.ip)}:${e.port}</code></td>
      <td>${esc(e.product || "")} ${esc(e.version || "")}${e.title ? `<div class="muted">${esc(e.title)}</div>` : ""}
        <div>${(e.flag || "").split(" ").filter(Boolean).map((x) => `<span class="flag">${esc(x)}</span>`).join("")}</div></td>
      <td>${[...(e.kev || []), ...(e.cves || []).filter((c) => !(e.kev || []).includes(c))].slice(0, 3).map((c) => `<code>${esc(c)}</code>`).join("<br>")}</td></tr>`).join("")}
    </table>
    <p class="muted" style="font-size:12px">IPs are masked: the tool targets companies, it is not a target list.</p>

    <h4>Footprint</h4>
    <ul class="plain">
      <li>${fmt(a.ips)} IPs · ${fmt(a.ports)} distinct ports · ${fmt(a.total_cves)} CVE matches (max CVSS ${a.max_cvss ?? "—"}, max EPSS ${a.max_epss != null ? (a.max_epss * 100).toFixed(0) + "%" : "—"})</li>
      ${a.kev_list?.length ? `<li>Known-exploited: ${a.kev_list.slice(0, 8).map(esc).join(", ")}</li>` : ""}
      ${a.ambient_kev_list?.length ? `<li class="muted">Version-inferred (low confidence): ${a.ambient_kev_list.slice(0, 4).map(esc).join(", ")}</li>` : ""}
      ${a.ntlm_domains?.length ? `<li>Leaked internal AD domain: <code>${esc(a.ntlm_domains[0])}</code></li>` : ""}
      ${a.cert_orgs?.length ? `<li>Legal entity on certificate: ${esc(a.cert_orgs.join("; "))}</li>` : ""}
      ${a.tech?.length ? `<li>Tech: ${esc(a.tech.slice(0, 10).join(", "))}</li>` : ""}
      <li>Network: ${esc(a.hosting_org || "—")}${a.owns_netblock ? " (company-registered netblock)" : ""} · identified via ${esc(a.entity_src)}</li>
    </ul>`;
  $("#drawer").classList.add("open");
  $("#scrim").classList.add("open");
  $("#drawer").setAttribute("aria-hidden", "false");
}
function closeDetail() {
  $("#drawer").classList.remove("open");
  $("#scrim").classList.remove("open");
  $("#drawer").setAttribute("aria-hidden", "true");
}

function renderPlays() {
  const byPlay = count(state.data.accounts, (a) => a.primary_play);
  $("#plays").innerHTML = byPlay.map(([p, n]) => {
    const hot = state.data.accounts.filter((a) => a.primary_play === p && a.tier === "Hot").length;
    return `<div class="card" data-play="${esc(p)}"><h3>${esc(p)}</h3><div class="n">${fmt(n)}</div>
      <p>${fmt(hot)} Hot · sell ${esc(PLAYS[p]?.pitch || "")}</p></div>`;
  }).join("");
  $("#campaigns").innerHTML = state.data.campaigns.slice(0, 40).map((c) => `
    <div class="card" data-cve="${esc(c.cve)}"><h3>${esc(c.cve)}</h3><div class="n">${fmt(c.accounts)}</div>
    <p>accounts exposed${c.ransomware ? " · <b style='color:var(--danger)'>ransomware-linked</b>" : ""}</p></div>`).join("");
}

function renderMethod() {
  const e = state.evaluation;
  const h = e?.heldout_compromise, sh = e?.split_half;
  $("#tab-method").innerHTML = `
  <h2>What this ranks</h2>
  <p>Every account is a company resolved from one day of internet-wide scan data (${state.data.stats.banners_scanned ? `${fmt(state.data.stats.banners_scanned)} service banners, ${fmt(state.data.stats.banners)} of them matched to a company` : `${fmt(state.data.stats.banners)} banners matched to a company`}).
  Each gets <b>Score = Need × (0.55 + 0.45·Fit) × Timing</b>:</p>
  <ul>
    <li><b>Need</b> is how acute the security pain is, from signals attackers themselves use: known-exploited CVEs (CISA KEV, ransomware-linked), exposed RDP/SMB/databases, perimeter devices, end-of-life software, OT/ICS, exposed AI/MCP endpoints, and hygiene gaps.</li>
    <li><b>Fit</b> says whether this is a real business worth calling: internet footprint, owns its network, TLS cert with a legal entity, multi-country, regulated sector, has a security owner.</li>
    <li><b>Timing</b> is why this week: recently weaponised CVEs, certificates about to expire (infra work under way), live compromise.</li>
  </ul>
  <h2>Signals that are not what they seem</h2>
  <ul>
    <li><b>Most "KEV" matches are noise.</b> They are inferred from version strings. HTTP/2 Rapid Reset alone matches ${fmt(state.data.stats.ambient_kevs?.[0]?.[1] || 0)} banners. CVEs matched on more than 1,000 banners are treated as <i>ambient</i> (low-weight hygiene) unless the scanner actively verified that host. Only 70 in 245k CVE matches in a sample were verified.</li>
    <li><b>Scanner probe names are not detections.</b> Banners from modules like <code>njrat</code> or <code>darktrack-rat</code> only show which probe was sent. Taken at face value they would flag facebook.com as running a RAT. Only fingerprinted C2 or tagged compromise counts.</li>
    <li><b>Whoever owns the netblock is often not who runs the box.</b> Left alone, telcos and hosting providers top every ranking because their customers' routers and VPSes are full of CVEs. Three data-driven tests remove them. Access ISPs show 8–42% consumer-device banners, against ≤1% for enterprises. Hosting orgs carry ≥10 other companies' certificates on their IPs. Providers stamp hostnames from a template (<code>host-NNN.dedicated.vsys.host</code>), giving ≤0.11 name templates per IP, while every organisation checked was ≥0.43. That removes ${fmt(state.data.stats.infra_dropped)} namespaces.</li>
    <li><b>NTLM leaks internal AD domain names</b>, security.txt yields an outreach contact, and OV certificates give the legal entity name.</li>
  </ul>
  ${h ? `<h2>Does it work?</h2>
  <p>There are no "will buy" labels in a scan file, so each test hides a signal from the score and checks whether the <i>other</i> signals still find those companies. Every test is compared with the naive approach: rank by footprint size.</p>
  <table><tr><th>Held-out label</th><th>Positives</th><th>AUC: score [95% CI]</th><th>AUC: size baseline</th><th>Top-10% lift (score vs size)</th></tr>
    ${[["Observed compromise (C2 / malware / compromised tag)", h], ["Scanner-verified vulnerability (all CVE signals withheld)", e.heldout_verified_vuln]].map(([n, x]) => `
    <tr><td>${n}</td><td>${fmt(x.positives)}</td><td><b>${x.auc_score}</b> [${x.auc_score_95ci.join("–")}]</td>
    <td>${x.auc_size_baseline} [${x.auc_size_baseline_95ci.join("–")}]</td><td>${x.lift_top10pct_score}× vs ${x.lift_top10pct_size_baseline}×</td></tr>`).join("")}
  </table>
  <p class="muted">The compromise test has only ${fmt(h.positives)} positives, so its interval is wide. The verified-vulnerability test (${fmt(e.heldout_verified_vuln.positives)} positives) shows that exposure and hygiene signals alone predict real, confirmed vulnerabilities.</p>
  <p><b>Reliability.</b> Scoring each company from two disjoint halves of its IPs gives Spearman ρ = ${sh.spearman_need} and ${(sh.tier_agreement * 100).toFixed(0)}% tier agreement (${fmt(sh.companies_with_4plus_ips)} companies with ≥4 IPs).</p>
  ${e.precision_audit ? `<p><b>Precision audit.</b> In the top domain-identified accounts, the share that are real organisations (not ISPs or hosting): ${e.precision_audit.p_at_10 * 100}% @10, ${e.precision_audit.p_at_20 * 100}% @20, ${e.precision_audit.p_at_50 * 100}% @50. The misses are ISP and hosting brands, the main open problem.</p>` : ""}
  <p><b>Which signals carry information?</b> Lift of each signal vs. observed compromise (only 16 positives, so read the ordering, not the exact numbers). NTLM leaking an internal AD domain is a quiet but strong one. Weights were set by hand and checked against this table, not fitted to it, to avoid overfitting 16 labels.</p>
  <table><tr><th>Signal</th><th>Companies</th><th>Lift</th></tr>
    ${Object.entries(e.signal_lift_vs_compromise || {}).slice(0, 8).map(([k, v]) => `<tr><td>${esc(SIGNAL_LABEL[k] || k)}</td><td>${fmt(v.companies)}</td><td>${v.lift_vs_base}×</td></tr>`).join("")}
  </table>` : ""}
  <h2>Cost</h2>
  <p>No LLM calls at runtime. Ingestion + scoring is deterministic and costs CPU only (see repository README for throughput). Every number in the UI can be traced to a banner.</p>`;
}

function toCsv(rows) {
  const cols = ["rank", "name", "entity", "score", "tier", "primary_play", "segment", "country", "ips", "sec_contact", "kev_list"];
  const q = (v) => `"${String(Array.isArray(v) ? v.join(" ") : v ?? "").replace(/"/g, '""')}"`;
  return [cols.join(","), ...rows.map((r) => cols.map((c) => q(r[c])).join(","))].join("\n");
}

function bind() {
  ["#q", "#f-tier", "#f-play", "#f-seg", "#f-country", "#f-ips", "#f-reg", "#f-contact", "#f-own", "#f-named"]
    .forEach((s) => $(s).addEventListener(s === "#q" ? "input" : "change", apply));
  $("#reset").onclick = () => {
    ["#q", "#f-tier", "#f-play", "#f-seg", "#f-country"].forEach((s) => ($(s).value = ""));
    $("#f-ips").value = 1;
    ["#f-reg", "#f-contact", "#f-own"].forEach((s) => ($(s).checked = false));
    $("#f-named").checked = true;
    apply();
  };
  $("#export").onclick = () => {
    const blob = new Blob([toCsv(state.filtered)], { type: "text/csv" });
    const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: "exposure-radar-accounts.csv" });
    a.click();
  };
  $("#more").onclick = () => { state.shown += PAGE; renderRows(); };
  $("#rows").addEventListener("click", (e) => { const tr = e.target.closest("tr"); if (tr) openDetail(tr.dataset.e); });
  $("#drawer .close").onclick = closeDetail;
  $("#scrim").onclick = closeDetail;
  document.addEventListener("keydown", (e) => e.key === "Escape" && closeDetail());
  document.querySelectorAll(".tab").forEach((t) => (t.onclick = () => switchTab(t.dataset.tab)));
  $("#plays").addEventListener("click", (e) => {
    const c = e.target.closest(".card"); if (!c) return;
    $("#f-play").value = c.dataset.play; switchTab("accounts"); apply();
  });
  $("#campaigns").addEventListener("click", (e) => {
    const c = e.target.closest(".card"); if (!c) return;
    $("#q").value = c.dataset.cve.toLowerCase(); $("#f-play").value = ""; switchTab("accounts"); apply();
  });
}
function switchTab(name) {
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === `tab-${name}`));
}

load().catch((err) => {
  document.querySelector("main").innerHTML = `<p style="color:var(--danger)">Failed to load data: ${esc(err.message)}</p>`;
});
