#!/usr/bin/env python3
"""
Recon Dashboard
===============
Interactive Streamlit UI built on top of the `recon` backend engine.

LEGAL NOTICE: This tool must only be used on assets you own or have written
permission to test. The rate limit (RPS) is low by default.

Run:
    streamlit run app.py                       # http://localhost:8501
    docker compose up dashboard                # Docker

Features:
  1) Target & rate (RPS) configuration
  2) Quick scan: one click runs every stage end-to-end automatically
  3) Expert mode: full settings + step-by-step manual flow with dynamic scope
  4) Live 403, critical JS and VERSION DISCLOSURE alerts + filterable table/chart
  5) In-UI wordlist management (text-area)
  6) Direct mode: enter targets manually and skip discovery
"""
from __future__ import annotations

import html as html_lib
import sys
import time
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core import security_checks as sec
from core.exceptions import ConfigError
from core.logger import setup_logging
import io
import tempfile
import zipfile


def zip_output_dir(root: Path) -> bytes:
    """Packs a scan output directory (outputs/<target>/) into a single in-memory .zip."""
    root = Path(root)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(root.rglob("*")):
            # "_" ile başlayan klasör/dosyalar araçların geçici girdi/çıktılarıdır (ffuf ham JSON,
            # host başına üretilmiş wordlist kopyaları); arşivi şişirmemek için dışarıda bırakılır.
            if p.is_file() and not any(part.startswith("_") for part in p.relative_to(root).parts):
                zf.write(p, arcname=p.relative_to(root.parent))
    return buf.getvalue()

from core.config import TOOL_DEFAULT_FLAGS
from dashboard.config_builder import build_config, guess_category, save_uploaded_wordlist
from dashboard.config_builder import builtin_wordlists as _builtin_wordlists
from dashboard.controller import STEP_LABELS, ScanController

setup_logging("INFO")

# Tam genişlik: yeni Streamlit sürümlerinde `use_container_width` kaldırılıyor (yerine width="stretch").
# requirements aralığındaki (>=1.40,<4) eski ve yeni sürümlerin ikisinde de çalışsın diye sürüme göre seçilir.
import inspect as _inspect
FULL_W = ({"width": "stretch"} if "width" in _inspect.signature(st.button).parameters
          else {"use_container_width": True})


@st.cache_data(show_spinner=False)
def builtin_wordlists() -> list[tuple[str, str, str]]:
    """Yerleşik wordlist kataloğu (satır sayılarıyla). Dosyalar her yeniden çizimde tekrar sayılmasın."""
    return _builtin_wordlists()


STAGES = ["ports", "crawl", "js", "dirs", "nuclei"]   # stages other than subdomains (canonical order)

# "Tool commands" section: user-editable behavior flags + a non-removable "auto" part.
# Editable tools (add/remove flags): subfinder, httpx, nmap, nuclei.
TOOL_EDITABLE = ["subfinder", "httpx", "nmap", "nuclei"]
# What happens when an external tool is NOT installed (shown in the Tool status panel).
TOOL_FALLBACK = {
    "subfinder": "root domain only — no passive subdomain discovery",
    "httpx":     "internal liveness prober",
    "katana":    "internal crawler",
    "ffuf":      "internal directory engine",
    "nmap":      "internal socket scanner (no service/version detection)",
    "nuclei":    "stage skipped — no vuln scan (no fabricated CVEs)",
}

TOOL_AUTO_PART = {   # the part the module always appends and that cannot be removed (informational)
    "subfinder": "subfinder -d <target> … + [editable] (+ proxy)",
    "httpx":     "httpx -json … + [editable] + rate/threads/timeout/header (stdin: hosts)",
    "nmap":      "nmap [editable] -p <ports> --max-rate … --host-timeout … -oX - <hosts>",
    "nuclei":    "nuclei -jsonl … + [editable] + rate/severity/exclude/templates (stdin: targets)",
}

st.set_page_config(page_title="Recon Dashboard", layout="wide", initial_sidebar_state="expanded")

CSS = """
<style>
  .block-container {padding-top: 2.2rem;}
  div[data-testid="stMetric"] {background:#11151c;border:1px solid #232b36;border-radius:12px;padding:14px 16px;}
  .recon-alert {background:#2a0d0f;border:1px solid #7f1d1d;color:#fecaca;border-radius:12px;
    padding:14px 18px;margin:6px 0;font-weight:600;}
  .recon-warn {background:#2a1e0b;border:1px solid #92610d;color:#fde8c0;border-radius:12px;
    padding:12px 18px;margin:6px 0;font-weight:600;}
  .recon-ok {background:#0c1f17;border:1px solid #14532d;color:#bbf7d0;border-radius:12px;padding:10px 16px;margin:6px 0;}
  .step-pill {display:inline-block;padding:4px 12px;border-radius:999px;margin-right:6px;font-size:12px;}
  .step-done {background:#14532d;color:#bbf7d0;}
  .step-active {background:#1e3a8a;color:#bfdbfe;}
  .step-todo {background:#1f2630;color:#9aa6b2;}
  h1 {font-size:1.7rem !important;}
  .muted {color:#8b97a5;font-size:13px;}
  /* --- Severity summary bar --- */
  .posture {display:flex;align-items:stretch;gap:14px;margin:4px 0 10px;flex-wrap:wrap;}
  .sev-strip {display:flex;gap:10px;flex-wrap:wrap;align-items:center;}
  .sev-chip {display:flex;flex-direction:column;align-items:center;min-width:92px;border-radius:12px;
    padding:8px 10px;border:1px solid #232b36;background:#11151c;}
  .sev-chip .n {font-size:1.5rem;font-weight:700;line-height:1;}
  .sev-chip .t {font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;margin-top:3px;color:#9aa6b2;}
  .sev-CRITICAL .n{color:#f87171;} .sev-HIGH .n{color:#fb923c;} .sev-MEDIUM .n{color:#fbbf24;}
  .sev-LOW .n{color:#60a5fa;} .sev-INFO .n{color:#94a3b8;}
  .sev-tag {display:inline-block;padding:1px 8px;border-radius:6px;font-size:11px;font-weight:700;}
  .tag-CRITICAL{background:#7f1d1d;color:#fecaca;} .tag-HIGH{background:#9a3412;color:#fed7aa;}
  .tag-MEDIUM{background:#92610d;color:#fde8c0;} .tag-LOW{background:#1e3a8a;color:#bfdbfe;}
  .tag-INFO{background:#334155;color:#cbd5e1;}
  /* Hide the top-right Streamlit toolbar / "running" indicator (toolbarMode fallback) */
  /* NOTE: never hide the whole stToolbar — in current Streamlit the button that RE-OPENS a collapsed
     sidebar lives inside it, so hiding it leaves the user with no way to get the sidebar back. */
  div[data-testid="stStatusWidget"], div[data-testid="stAppDeployButton"], span[data-testid="stMainMenu"],
  #MainMenu, header [data-testid="stDecoration"] {display:none !important;}
  [data-testid="stExpandSidebarButton"], [data-testid="stSidebarCollapsedControl"] {display:flex !important; visibility:visible !important;}
  /* "Scan in progress" indicator: a calm, non-blinking line instead of a progress bar */
  .recon-run {display:flex;align-items:center;gap:10px;background:#0e1830;border:1px solid #1e3a8a;
    color:#bfdbfe;border-radius:12px;padding:10px 16px;margin:6px 0;font-weight:600;}
  .recon-run .dot {width:9px;height:9px;border-radius:50%;background:#60a5fa;animation:pulse 1.1s ease-in-out infinite;}
  @keyframes pulse {0%,100%{opacity:.35;} 50%{opacity:1;}}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

# ---------------------------------------------------------------- session state
SS = st.session_state
SS.setdefault("controller", None)
SS.setdefault("phase", "config")          # config | running:<mod> | review:<mod> | done
SS.setdefault("stages", STAGES.copy())     # stages to run (excluding subdomains)
SS.setdefault("skip_recon", False)
SS.setdefault("expert", False)             # Expert mode: full settings + manual stage flow
SS.setdefault("auto_run", True)            # Quick scan: stages run end-to-end automatically
SS.setdefault("live_hosts", [])
SS.setdefault("js_findings", [])
SS.setdefault("dir_hits", [])
SS.setdefault("version_leaks", [])
SS.setdefault("findings", [])          # unified security findings (header/TLS/takeover/version/CVE)
SS.setdefault("open_ports", [])        # open-port inventory
SS.setdefault("uploaded_wordlists", [])        # [{name, path, category}]
if "wl_dir" not in SS:   # setdefault(…, mkdtemp()) her yeniden çizimde boş bir klasör daha yaratıyordu
    SS["wl_dir"] = tempfile.mkdtemp(prefix="recon_wl_")


def reset_session() -> None:
    ctrl = SS.get("controller")
    if ctrl is not None:
        ctrl.cancel()   # arka plandaki tarama (ve harici araç) hedefe istek atmaya devam etmesin
    for k in ("controller", "phase", "live_hosts", "js_findings", "dir_hits",
              "version_leaks", "findings", "open_ports", "scope_editor", "report_root",
              "zip_bytes", "unified_cache"):
        SS.pop(k, None)
    SS["phase"] = "config"


def contains(df: pd.DataFrame, columns: list[str], query: str) -> pd.DataFrame:
    """Büyük/küçük harf duyarsız düz metin araması (vektörel; satır satır apply() değil)."""
    hay = df[columns[0]].astype(str)
    for c in columns[1:]:
        hay = hay + " " + df[c].astype(str)
    return df[hay.str.contains(query, case=False, regex=False)]


def drain_into_state() -> None:
    ctrl: ScanController = SS["controller"]
    for kind, payload in ctrl.drain_events():
        if kind == "live_host":
            SS["live_hosts"].append(payload)
        elif kind == "js_finding":
            SS["js_findings"].append(payload)
        elif kind == "dir_hit":
            SS["dir_hits"].append(payload)
        elif kind == "version_leak":
            SS["version_leaks"].append(payload)
        elif kind == "finding":
            SS["findings"].append(payload)
        elif kind == "port":
            SS["open_ports"].append(payload)


def stage_after(current: str | None) -> str | None:
    """First stage after subdomains; the next stage after a given stage."""
    stages = SS["stages"]
    if current == "subdomains" or current is None:
        return stages[0] if stages else None
    if current in stages:
        i = stages.index(current)
        return stages[i + 1] if i + 1 < len(stages) else None
    return None


# ================================================================ SIDEBAR: config
with st.sidebar:
    st.markdown("### Scan setup")
    locked = SS["controller"] is not None

    # Pro default: one click, fully automatic end-to-end. Expert mode → full settings + manual flow.
    expert = st.toggle("Expert mode", value=SS.get("expert", False), disabled=locked,
                       help="Off (recommended): one click runs every stage automatically with smart "
                            "defaults. On: opens the rate/stage/wordlist/Nuclei/command settings and "
                            "enables step-by-step (manual) progression.")
    SS["expert"] = expert

    # ---- PRIMARY (always visible) ----
    mode = st.radio("Mode", ["Full recon", "Direct — enter targets"],
                    index=0 if not SS.get("skip_recon") else 1, disabled=locked,
                    help="Full recon: subdomain discovery + liveness. Direct: skip discovery, enter targets manually.")
    skip = mode.startswith("Direct")
    target = st.text_input("Target" + (" (optional)" if skip else ""),
                           value=SS.get("target", ""), placeholder="example.com",
                           disabled=locked,
                           help="Full recon: root domain to scan (required). "
                                "Direct: may be left blank — used only as the output folder name.")
    targets_text = ""
    if skip:
        targets_text = st.text_area("Targets (one host/IP per line)", height=110, disabled=locked,
                                     value=SS.get("targets_text", ""),
                                     placeholder="app.example.com\napi.example.com\n93.184.216.34\nhttps://admin.example.com",
                                     help="Each host or IP entered is scanned directly and individually. "
                                          "No root domain required; scope = the targets you enter.")

    if not expert:
        # -------- QUICK SCAN: smart defaults (no panels) --------
        rate, threads, timeout = SS.get("rate", 10), SS.get("threads", 10), SS.get("timeout", 10)
        dir_engine, proxy, out_dir = "auto", "", SS.get("out_dir", "outputs")
        stages = STAGES.copy()
        wordlist_choice = [(path, cat) for _, path, cat in builtin_wordlists()]
        auto_tech, words, use_manual = True, "", False
        nuclei_severity = ["critical", "high", "medium"]
        nuclei_intrusive, nuclei_templates, nuclei_exclude_tags = False, [], []
        nuclei_tpl_text, nuclei_excl_text = "", ""
        tool_args_ui = {t: " ".join(TOOL_DEFAULT_FLAGS[t]) for t in TOOL_EDITABLE}
        if not locked:
            st.caption("**Quick scan** — smart defaults: RPS 10 · all stages · all built-in "
                       "wordlists · Nuclei safe mode. Stages flow from start to finish automatically; "
                       "no manual confirmation in between. Open **Expert mode** to change settings.")
    else:
        # ---- ADVANCED (collapsed) ----
        with st.expander("Advanced settings", expanded=False):
            rate = st.slider("Rate limit (req/s)", 1, 100, SS.get("rate", 10), disabled=locked,
                             help="Maximum requests per second across all modules.")
            c1, c2 = st.columns(2)
            threads = c1.number_input("Threads", 1, 100, SS.get("threads", 10), disabled=locked)
            timeout = c2.number_input("Timeout (s)", 1, 120, SS.get("timeout", 10), disabled=locked)
            dir_engine = st.selectbox("Directory engine", ["auto", "internal", "ffuf"], disabled=locked)
            proxy = st.text_input("Proxy", value="", placeholder="http://127.0.0.1:8080", disabled=locked)
            out_dir = st.text_input("Output dir", value=SS.get("out_dir", "outputs"), disabled=locked)
            stages = st.multiselect("Stages", STAGES, default=SS.get("stages", STAGES),
                                    format_func=lambda s: STEP_LABELS[s], disabled=locked,
                                    help="Discovery is always the first stage (in Full recon mode).")

        # ---- WORDLISTS (collapsed) ----
        with st.expander("Wordlists", expanded=False):
            st.caption("Tick the lists for directory scanning. You can upload your own .txt list on top of "
                       "the built-ins, or tick only one (e.g. backups) and scan with just that.")
            if not locked:
                uploads = st.file_uploader("Add wordlist (.txt)", type=["txt"],
                                           accept_multiple_files=True, key="wl_uploader")
                for uf in uploads or []:
                    if not any(u["name"] == uf.name for u in SS["uploaded_wordlists"]):
                        path = save_uploaded_wordlist(uf.name, uf.getvalue(), Path(SS["wl_dir"]))
                        SS["uploaded_wordlists"].append(
                            {"name": uf.name, "path": str(path), "category": guess_category(uf.name)})
            wordlist_choice: list[tuple[str, str]] = []
            st.caption("Built-in")
            for label, path, cat in builtin_wordlists():
                if st.checkbox(label, value=True, key=f"wl_builtin_{cat}", disabled=locked):
                    wordlist_choice.append((path, cat))
            if SS["uploaded_wordlists"]:
                st.caption("Uploaded")
            for u in SS["uploaded_wordlists"]:
                w1, w2 = st.columns([5, 1])
                checked = w1.checkbox(f"{u['name']} ({u['category']}, uploaded)", value=True,
                                      key=f"wl_up_{u['name']}", disabled=locked)
                if not locked and w2.button("x", key=f"wl_rm_{u['name']}", help="Remove"):
                    SS["uploaded_wordlists"] = [x for x in SS["uploaded_wordlists"] if x["name"] != u["name"]]
                    st.rerun()
                if checked:
                    wordlist_choice.append((u["path"], u["category"]))
            auto_tech = st.checkbox("Auto-add by technology (PHP, ASP.NET, Java, Node...)",
                                    value=True, key="wl_auto_tech", disabled=locked,
                                    help="Automatically adds the relevant list based on detected infrastructure.")
            words = st.text_area("Custom paths (one per line)", value=SS.get("words", ""), height=90,
                                 disabled=locked, placeholder="admin\nbackup.zip\n.git/HEAD")
            use_manual = st.checkbox("Use custom paths", value=True, disabled=locked)

        # ---- VULN & PORTS (collapsed) ----
        with st.expander("Vuln scan (Nuclei) & ports", expanded=False):
            nuclei_severity = st.multiselect("Nuclei severity", ["critical", "high", "medium", "low", "info"],
                                             default=SS.get("nuclei_severity", ["critical", "high", "medium"]),
                                             disabled=locked, help="Empty = all severities.")
            nuclei_intrusive = st.checkbox("Intrusive mode", value=False, disabled=locked,
                                           help="ENABLES dangerous templates (dos/fuzz/brute). Use only on "
                                                "targets you have written permission to test.")
            if nuclei_intrusive:
                st.warning("Intrusive mode is on — potentially damaging templates will run. Authorized target required.")
            nuclei_tpl_text = st.text_area("Custom templates (path per line)", height=70, disabled=locked,
                                           value=SS.get("nuclei_tpl", ""),
                                           placeholder="/templates/cves/\n/templates/my-php-8.1.yaml",
                                           help="Your own technology/version-specific Nuclei template directory/file.")
            nuclei_excl_text = st.text_input("Exclude tags", value=SS.get("nuclei_excl", ""), disabled=locked,
                                             placeholder="network, dns",
                                             help="Extra tags to exclude (comma-separated). Dangerous tags are "
                                                  "already excluded by default.")
            nuclei_templates = [l.strip() for l in nuclei_tpl_text.splitlines() if l.strip()]
            nuclei_exclude_tags = [t.strip() for t in nuclei_excl_text.split(",") if t.strip()]
            st.caption("Note: Nuclei runs if installed; otherwise this stage is skipped (no fabricated CVEs). "
                       "Port scanning uses nmap if present (service+version detection), otherwise the internal scanner.")

        # ---- TOOL COMMANDS (collapsed) — EDIT the command (add/remove flags) ----
        with st.expander("Tool commands (advanced)", expanded=False):
            st.caption("Edit each tool's flags directly: they come pre-filled and you can **add or remove** "
                       "whatever you want (e.g. deleting `-sV` from nmap). The required part (output "
                       "format/target — the 'auto' line) is always appended and cannot be removed. "
                       "Leave blank to fall back to the default.")
            tool_args_ui = {}
            for tool in TOOL_EDITABLE:
                default_str = " ".join(TOOL_DEFAULT_FLAGS[tool])
                tool_args_ui[tool] = st.text_input(
                    f"{tool} — flags", value=SS.get(f"tf_{tool}", default_str),
                    key=f"tf_{tool}", disabled=locked)
                st.caption(f"auto: `{TOOL_AUTO_PART[tool]}`")

    st.divider()
    if not locked:
        start_label = "Quick scan" if not expert else "Start (manual, step-by-step)"
        if st.button(start_label, type="primary", **FULL_W):
            try:
                if not stages and skip:
                    st.error("In Direct mode you must select at least one stage.")
                    st.stop()
                if "dirs" in stages and not wordlist_choice and not (use_manual and words.strip()):
                    st.error("Directory scan is selected but no wordlist is ticked (Wordlists section).")
                    st.stop()
                if skip:
                    # Direct mode: root domain NOT required. Take targets from the textarea, each individually.
                    parsed = ScanController.parse_targets(targets_text)
                    if not parsed:
                        st.error("In Direct mode, enter at least one valid target (host or IP).")
                        st.stop()
                    label = target.strip() or parsed[0]   # output folder label; first target is enough
                else:
                    if not target.strip():
                        st.error("Enter a target domain for Full recon (or switch to Direct mode).")
                        st.stop()
                    label = target
                cfg = build_config(label, rate_limit=float(rate), threads=int(threads), timeout=int(timeout),
                                   output_dir=out_dir, dir_engine=dir_engine, direct=skip,
                                   custom_words=words if use_manual else "",
                                   wordlist_files=wordlist_choice, auto_tech=auto_tech, proxy=proxy or None,
                                   nuclei_intrusive=nuclei_intrusive, nuclei_templates=nuclei_templates,
                                   nuclei_exclude_tags=nuclei_exclude_tags, nuclei_severity=nuclei_severity,
                                   tool_args=tool_args_ui)
                SS.update(target=target, rate=rate, threads=threads, timeout=timeout, out_dir=out_dir,
                          words=words, stages=stages, skip_recon=skip, targets_text=targets_text,
                          nuclei_severity=nuclei_severity, nuclei_tpl=nuclei_tpl_text, nuclei_excl=nuclei_excl_text,
                          auto_run=not expert)
                ctrl = ScanController(cfg)
                SS["controller"] = ctrl
                SS["phase"] = "running:subdomains"
                if skip:
                    _, dropped = ctrl.start_seed(targets_text)
                    if dropped:
                        st.warning(f"Dropped as out of scope: {', '.join(dropped)}")
                else:
                    ctrl.start_module("subdomains")
                st.rerun()
            except ConfigError as exc:
                st.error(f"Invalid setting: {exc}")
            except Exception as exc:
                st.error(f"Could not start: {exc}")
    else:
        _ctrl = SS["controller"]
        if SS["phase"].startswith("running:") and not _ctrl.cancelled:
            if st.button("Stop scan", **FULL_W,
                         help="Stops sending requests and kills the running external tool. "
                              "Results collected so far are kept; you can still write the report."):
                _ctrl.cancel()
                st.rerun()
        if st.button("New scan", **FULL_W,
                     help="Stops any running scan and returns to the setup screen."):
            reset_session()
            st.rerun()
        with st.expander("Tool status", expanded=False):
            status = SS["controller"].tool_status()
            n_ok = sum(1 for v in status.values() if v)
            st.caption(f"External tools in this environment — {n_ok}/{len(status)} installed. "
                       "Missing tools fall back to a built-in engine (except Nuclei, which is skipped).")
            rows = []
            for tool, ok in status.items():
                if ok:
                    rows.append(f"| **{tool}** | installed | used directly |")
                else:
                    rows.append(f"| {tool} | not found | {TOOL_FALLBACK.get(tool, 'internal fallback')} |")
            st.markdown("| Tool | Status | Fallback |\n|---|---|---|\n" + "\n".join(rows))

# ================================================================ HEADER
st.title("Recon Dashboard")
st.markdown('<span class="muted">Attack-surface discovery & exposure assessment · authorized targets only</span>',
            unsafe_allow_html=True)

if SS["controller"] is None:
    st.info("Enter a target on the left and press **Quick scan** — every stage (discovery → ports → "
            "crawl → JS → directories → Nuclei) runs end-to-end automatically and produces a single "
            "security table + report. Open **Expert mode** to tune rate, stage selection, wordlists, "
            "Nuclei and tool commands manually, or to progress stage by stage. Use **Direct** mode to "
            "skip discovery and enter targets manually.")
    st.stop()

ctrl: ScanController = SS["controller"]

# Step indicator
first_label = "Targets (manual)" if SS["skip_recon"] else STEP_LABELS["subdomains"]
plan_pills = [("subdomains", first_label)] + [(s, STEP_LABELS[s]) for s in SS["stages"]]
done = set(ctrl.completed_steps())
active = SS["phase"].split(":")[-1] if ":" in SS["phase"] else None
html = []
for step, label in plan_pills:
    cls = "step-done" if step in done else ("step-active" if step == active else "step-todo")
    html.append(f'<span class="step-pill {cls}">{label}</span>')
st.markdown(" ".join(html), unsafe_allow_html=True)
st.divider()


# ---------------------------------------------------------------- finding model
def build_unified_findings() -> list[dict]:
    """Merges all sources into a single severity-ranked finding list:
    security (header/TLS/takeover/version) + JS secrets + critical directory exposures.
    Rebuilt only when new events arrived (the lists are append-only, so their sizes are the version)."""
    version = (len(SS["findings"]), len(SS["js_findings"]), len(SS["dir_hits"]))
    cached = SS.get("unified_cache")
    if cached and cached[0] == version:
        return cached[1]
    out = sec.merge_findings(SS["findings"], SS["js_findings"], SS["dir_hits"])
    SS["unified_cache"] = (version, out)
    return out


def render_posture(unified: list[dict]) -> None:
    """Severity counts only. (The old A–F "security grade" was removed: a single letter derived from the
    worst finding says little about a target and reads as a verdict the tool cannot back up.)"""
    counts = sec.severity_counts(unified)
    chips = "".join(
        f'<div class="sev-chip sev-{s}"><span class="n">{counts.get(s,0)}</span>'
        f'<span class="t">{s}</span></div>' for s in sec.SEVERITIES)
    st.markdown(f'<div class="posture"><div class="sev-strip">{chips}</div></div>',
                unsafe_allow_html=True)


# ---------------------------------------------------------------- live panels
def render_alerts() -> None:
    unified = build_unified_findings()
    render_posture(unified)
    dir_403 = [h for h in SS["dir_hits"] if h.get("status") == 403]
    host_403 = [h for h in SS["live_hosts"] if h.get("status_code") == 403]
    high_js = [f for f in SS["js_findings"] if f.get("severity") == "HIGH"]
    vleaks = SS["version_leaks"]
    crit = [f for f in unified if f.get("severity") == "CRITICAL"]
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Live hosts", len(SS["live_hosts"]))
    c2.metric("Critical+High", sum(1 for f in unified if f.get("severity") in ("CRITICAL", "HIGH")))
    c3.metric("Critical JS (HIGH)", len(high_js))
    c4.metric("403 (host+dir)", len(dir_403) + len(host_403))
    c5.metric("Version disclosure", len(vleaks))
    if crit:
        titles = html_lib.escape(", ".join(sorted({str(f.get("title", "")) for f in crit}))[:160])
        st.markdown(f'<div class="recon-alert">{len(crit)} CRITICAL finding(s): {titles}.</div>',
                    unsafe_allow_html=True)
    if high_js:
        st.markdown(f'<div class="recon-alert">{len(high_js)} critical JS secret leak(s) detected '
                    f'(API key/token/password).</div>', unsafe_allow_html=True)
    if dir_403 or host_403:
        st.markdown(f'<div class="recon-warn">{len(dir_403) + len(host_403)} × 403 Forbidden — '
                    f'access-restricted but existing resources.</div>', unsafe_allow_html=True)


def render_hosts_table(selectable: bool) -> list[str] | None:
    if not SS["live_hosts"]:
        st.caption("No live hosts yet.")
        return None
    leak_by_url: dict[str, list[str]] = {}
    for v in SS["version_leaks"]:
        leak_by_url.setdefault(v["url"], []).append(f"{v['header']}: {v['value']}")
    rows = []
    for h in SS["live_hosts"]:
        rows.append({"Sel": True, "URL": h["url"], "Code": h.get("status_code"),
                     "Title": (h.get("title") or "")[:50],
                     "Server": h.get("webserver") or "",
                     "Technologies": ", ".join(h.get("technologies") or []),
                     "Version leak": " | ".join(leak_by_url.get(h["url"].rstrip("/"), leak_by_url.get(h["url"], [])))})
    rows.sort(key=lambda r: r["URL"])     # hosts arrive live, in completion order
    df = pd.DataFrame(rows)
    codes = sorted({r["Code"] for r in rows if r["Code"] is not None})
    f1, f2 = st.columns([1, 2])
    pick = f1.multiselect("Status code filter", codes, default=codes, key="host_code_filter")
    q = f2.text_input("Search (URL/technology)", key="host_q", placeholder="e.g. api, tomcat, 403")
    view = df[df["Code"].isin(pick)]
    if q:
        view = contains(view, ["URL", "Technologies", "Code"], q)
    if selectable:
        edited = st.data_editor(view, hide_index=True, **FULL_W,
                                column_config={"Sel": st.column_config.CheckboxColumn(required=True)},
                                disabled=["URL", "Code", "Title", "Server", "Technologies", "Version leak"],
                                key="scope_editor")
        return edited.loc[edited["Sel"], "URL"].tolist()
    st.dataframe(view, hide_index=True, **FULL_W)
    return None


def render_js_table() -> None:
    if not SS["js_findings"]:
        st.caption("No JS findings yet.")
        return
    st.caption("**HIGH/MEDIUM** rows are exact-format matches (AWS/Google/GitHub keys, JWT, private keys…) — "
               "pattern-based, not keyword-based. **LOW `keyword:*`** rows are word-based: an `api_key`/`secret`/"
               "`token`/`password`-style word used in an assignment with a non-trivial value. The `Match` column "
               "shows exactly what matched so you can judge each one.")
    df = pd.DataFrame(SS["js_findings"]).rename(
        columns={"severity": "Severity", "rule": "Rule", "url": "URL", "line_no": "Line", "match": "Match"})
    sev = st.multiselect("Severity filter", ["HIGH", "MEDIUM", "LOW"], default=["HIGH", "MEDIUM", "LOW"], key="js_sev")
    q = st.text_input("Search (rule/URL)", key="js_q")
    view = df[df["Severity"].isin(sev)]
    if q:
        view = contains(view, ["Rule", "URL"], q)
    st.dataframe(view[["Severity", "Rule", "URL", "Line", "Match"]], hide_index=True, **FULL_W)


def render_dir_table() -> None:
    if not SS["dir_hits"]:
        st.caption("No discovered paths yet.")
        return
    st.caption(f"**Every** path the directory/fuzzing scan found — {len(SS['dir_hits'])} in total, with their "
               "HTTP status codes. This is the full list (common, sensitive and backup alike), not only the "
               "sensitive ones. Category shows why a path was tested; **Verified** marks content-confirmed files.")
    df = pd.DataFrame(SS["dir_hits"]).rename(
        columns={"status": "Code", "url": "URL", "category": "Category", "length": "Length", "verified": "Verified"})
    codes = sorted(df["Code"].unique().tolist())
    f1, f2 = st.columns([1, 2])
    pick = f1.multiselect("Status code", codes, default=codes, key="dir_codes",
                          help="All codes are selected by default — untick to narrow down.")
    q = f2.text_input("Search (URL/category)", key="dir_q", placeholder="e.g. admin, api, .env, 301")
    view = df[df["Code"].isin(pick)]
    if q:
        view = contains(view, ["URL", "Category", "Code"], q)
    view = view.sort_values(["Code", "URL"])
    st.dataframe(view[["Code", "URL", "Category", "Length", "Verified"]], hide_index=True, **FULL_W)
    with st.expander("Status code distribution (chart)", expanded=False):
        st.bar_chart(view.groupby("Code").size().rename("count").reset_index().set_index("Code"), height=180)


def render_findings_table(unified: list[dict]) -> None:
    """Unified security findings: severity-colored, category/severity filtered, live search."""
    if not unified:
        st.caption("No security findings yet. They collect here as discovery/analysis progresses.")
        return
    cats = sorted({f.get("category", "") for f in unified})
    f1, f2, f3 = st.columns([1.2, 1.2, 2])
    # Note: the key depends on the current option set. As the scan progresses and new categories/severities
    # appear, the filter automatically covers them all (late-arriving HIGH findings are not hidden).
    sev_opts = [s for s in sec.SEVERITIES if any(f.get("severity") == s for f in unified)] or sec.SEVERITIES
    # INFO (hardening notes, version banners, public files) is hidden by default so real findings are
    # not buried; tick INFO in the filter to see them.
    actionable = [s for s in sec.SEVERITIES if s != "INFO"]
    sevs = f1.multiselect("Severity", sec.SEVERITIES, default=actionable,
                          key="fnd_sev_" + "".join(s[0] for s in sev_opts),
                          help="INFO rows (missing hardening headers, version banners, public files) are "
                               "hidden by default. Add INFO here to show them.")
    pick_cat = f2.multiselect("Category", cats, default=cats, key="fnd_cat_" + "_".join(cats))
    q = f3.text_input("Search (title/target/evidence)", key="fnd_q", placeholder="e.g. hsts, takeover, .env")
    view = [f for f in unified if f.get("severity") in sevs and f.get("category") in pick_cat]
    if q:
        ql = q.lower()
        view = [f for f in view
                if ql in (str(f.get("title")) + str(f.get("target")) + str(f.get("evidence"))).lower()]
    hidden_info = sum(1 for f in unified if f.get("severity") == "INFO") if "INFO" not in sevs else 0
    st.caption(f"Showing {len(view)} / {len(unified)} findings"
               + (f" · {hidden_info} informational hidden" if hidden_info else ""))
    has_cvss = any(f.get("cvss") is not None for f in view)
    rows = []
    for f in view:
        row = {"Severity": f["severity"], "Category": f.get("category"), "Title": f.get("title"),
               "Target": f.get("target")}
        if has_cvss:
            row["CVSS"] = f.get("cvss")
            row["CVE"] = f.get("cve", "")
        row["Evidence"] = f.get("evidence")
        row["Remediation"] = f.get("remediation")
        rows.append(row)
    df = pd.DataFrame(rows)
    sev_rank = {s: i for i, s in enumerate(sec.SEVERITIES)}
    if not df.empty:
        df = df.sort_values("Severity", key=lambda col: col.map(sev_rank))

    def _row_style(r):
        color = {"CRITICAL": "#7f1d1d", "HIGH": "#9a3412", "MEDIUM": "#92610d",
                 "LOW": "#1e3a8a", "INFO": "#334155"}.get(r["Severity"], "")
        return [f"background-color:{color};color:#f8fafc" if c == "Severity" else "" for c in r.index]

    styled = df.style.apply(_row_style, axis=1) if not df.empty else df
    colcfg = {"Evidence": st.column_config.TextColumn(width="medium"),
              "Remediation": st.column_config.TextColumn(width="large")}
    if has_cvss:
        colcfg["CVSS"] = st.column_config.NumberColumn(format="%.1f", width="small")
    st.dataframe(styled, hide_index=True, **FULL_W, column_config=colcfg)


def render_version_table() -> None:
    if not SS["version_leaks"]:
        st.caption("No version/banner disclosure findings.")
        return
    df = pd.DataFrame(SS["version_leaks"]).rename(
        columns={"url": "URL", "header": "Header", "value": "Value", "version": "Version"})
    q = st.text_input("Search (host/header)", key="ver_q")
    view = df
    if q:
        view = contains(view, ["URL", "Header", "Value"], q)
    st.dataframe(view[["URL", "Header", "Value", "Version"]], hide_index=True, **FULL_W)


def render_ports_table() -> None:
    if not SS["open_ports"]:
        st.caption("No open-port findings yet.")
        return
    from modules.port_scan import RISKY_SERVICES
    rows = [{"Host": p.get("host"), "Port": p.get("port"), "Service": p.get("service"),
             "Risk": "risky" if p.get("port") in RISKY_SERVICES else ""} for p in SS["open_ports"]]
    df = pd.DataFrame(rows).sort_values(["Host", "Port"])
    q = st.text_input("Search (host/service)", key="port_q", placeholder="e.g. redis, 3306, api")
    if q:
        df = contains(df, ["Host", "Service", "Port"], q)
    st.dataframe(df, hide_index=True, **FULL_W)


def render_result_tabs() -> None:
    unified = build_unified_findings()
    label = f"Findings ({len(unified)})" if unified else "Findings"
    ports_label = f"Ports ({len(SS['open_ports'])})" if SS["open_ports"] else "Ports"
    dirs_label = f"Directories ({len(SS['dir_hits'])})" if SS["dir_hits"] else "Directories"
    js_label = f"JS secrets ({len(SS['js_findings'])})" if SS["js_findings"] else "JS secrets"
    t = st.tabs([label, "Hosts", ports_label, "Version leaks", js_label, dirs_label])
    with t[0]:
        render_findings_table(unified)
    with t[1]:
        render_hosts_table(selectable=False)
    with t[2]:
        render_ports_table()
    with t[3]:
        render_version_table()
    with t[4]:
        render_js_table()
    with t[5]:
        render_dir_table()


# ================================================================ MAIN BODY
phase = SS["phase"]

if phase.startswith("running:"):
    name = phase.split(":")[1]
    busy = "Probing targets" if (name == "subdomains" and SS["skip_recon"]) else STEP_LABELS[name]

    # Two "fragments" keep the page calm and cheap while a stage runs:
    #   * status (every 1 s)  — drains the event queue, updates the timer, detects stage completion.
    #   * results (every 3 s) — re-renders the alert bar + tables. These are the expensive part
    #     (DataFrames for thousands of rows), so they are NOT rebuilt every second any more.
    # The alert/metric bar lives inside the fragment, so it now updates live during a stage
    # (it used to be drawn once, before the fragment, and stayed stale until the stage ended).
    @st.fragment(run_every=1.0)
    def _live_status() -> None:
        drain_into_state()
        run = ctrl.runs.get(name)
        elapsed = int(time.monotonic() - run.started_at) if run else 0
        note = "Stopping…" if ctrl.cancelled else f"Scan in progress — {busy}"
        st.markdown(
            f'<div class="recon-run"><span class="dot"></span>'
            f'<span>{note} · {elapsed}s</span></div>',
            unsafe_allow_html=True)
        if run and run.status != "running":
            if run.status == "ok":
                ctrl.mark_completed(name)
            SS["phase"] = f"review:{name}"
            st.rerun()   # stage done: full refresh to move to the review screen

    @st.fragment(run_every=3.0)
    def _live_results() -> None:
        render_alerts()
        st.divider()
        render_result_tabs()

    _live_status()
    _live_results()

elif phase.startswith("review:"):
    drain_into_state()          # events emitted between the last tick and stage completion
    render_alerts()
    st.divider()
    name = phase.split(":")[1]
    run = ctrl.runs.get(name)
    stopped = ctrl.cancelled or bool(run and run.status == "cancelled")

    # --- QUICK SCAN: advance automatically between stages without stopping ---
    # Scope = all live hosts; start the next stage if any, otherwise write the report and finish.
    # On error, stop auto-advancing and show the error in the manual screen below.
    if SS.get("auto_run") and not stopped and not (run and run.status == "failed"):
        nxt_auto = stage_after(name)
        if name == "subdomains":
            chosen = [h["url"] for h in SS["live_hosts"]]
            if chosen:
                ctrl.set_scope(chosen)
        if nxt_auto:
            SS["phase"] = f"running:{nxt_auto}"
            ctrl.start_module(nxt_auto)
            st.rerun()
        else:
            SS["report_root"] = str(ctrl.write_reports())
            SS["phase"] = "done"
            st.rerun()

    label = ("Target list" if SS["skip_recon"] and name == "subdomains" else STEP_LABELS[name])
    if stopped:
        st.warning(f"Scan stopped during: {label}. Results collected so far are kept below — "
                   "you can write the report, or start a new scan from the sidebar.")
    elif run and run.status == "failed":
        st.error(f"{label} failed: {run.error}")
    else:
        st.markdown(f'<div class="recon-ok">{label} — complete.</div>', unsafe_allow_html=True)
    summary = ctrl.module_summary(name)
    if summary:
        cols = st.columns(len(summary))
        for col, (k, v) in zip(cols, summary.items()):
            col.metric(k, v if not isinstance(v, dict) else sum(v.values()))

    nxt = stage_after(name)

    if stopped:
        render_result_tabs()
        st.divider()
        if st.button("Finish & write report", type="primary"):
            SS["report_root"] = str(ctrl.write_reports()); SS["phase"] = "done"; st.rerun()
    elif name == "subdomains":
        st.subheader("Scope — select the hosts to scan")
        n_live = len(SS["live_hosts"])
        st.info(f"The **checkboxes in the “Sel” column** of the table below decide which hosts get scanned. "
                f"All {n_live} live hosts arrive **pre-selected** — untick any you don't want to scan, then "
                f"press **Next**. The following stages run only on the selected hosts.")
        selected = render_hosts_table(selectable=True)

        # Also show the unresponsive (non-live) subdomains — clarity for "10 found, 4 live"
        live_names = {lh["url"].split("://")[-1].split("/")[0].split(":")[0] for lh in SS["live_hosts"]}
        live_names |= {lh.get("host") for lh in SS["live_hosts"]}
        dead = sorted(h for h in ctrl.ctx.subdomains if h not in live_names)
        if dead:
            with st.expander(f"Unresponsive subdomains ({len(dead)}) — not scanned", expanded=False):
                st.caption("These were found during subfinder/discovery but did not respond to the liveness check "
                           "(closed, no DNS, or unreachable). Full list is in the output's subdomains/dead.txt file.")
                st.code("\n".join(dead))
        st.divider()
        if nxt:
            if st.button(f"Next: {STEP_LABELS[nxt]}", type="primary"):
                chosen = selected if selected is not None else [h["url"] for h in SS["live_hosts"]]
                if not chosen:
                    st.warning("You must select at least one host.")
                else:
                    ctrl.set_scope(chosen)
                    SS["phase"] = f"running:{nxt}"
                    ctrl.start_module(nxt)
                    st.rerun()
        else:
            st.info("No other stage selected.")
            if st.button("Finish & write report", type="primary"):
                SS["report_root"] = str(ctrl.write_reports()); SS["phase"] = "done"; st.rerun()
    else:
        render_result_tabs()
        st.divider()
        if nxt:
            if st.button(f"Next: {STEP_LABELS[nxt]}", type="primary"):
                SS["phase"] = f"running:{nxt}"
                ctrl.start_module(nxt)
                st.rerun()
        else:
            if st.button("Finish & write report", type="primary"):
                SS["report_root"] = str(ctrl.write_reports()); SS["phase"] = "done"; st.rerun()

elif phase == "done":
    render_alerts()
    st.divider()
    st.success(f"Scan complete. Output: `{SS.get('report_root', ctrl.output.root)}`")
    root = Path(SS.get("report_root", str(ctrl.output.root)))
    # write_reports() already wrote report.md, summary.json and the unified findings (md + json)
    # into the output folder, so the single .zip holds EVERYTHING.
    render_result_tabs()
    st.divider()
    # ONE download: the whole output folder in a single .zip.
    if root.is_dir():
        if "zip_bytes" not in SS:      # build the archive once, not on every widget interaction
            SS["zip_bytes"] = zip_output_dir(root)
        st.download_button("Download output (.zip)", SS["zip_bytes"],
                           file_name=f"{ctrl.config.target}_output.zip", mime="application/zip",
                           **FULL_W, type="primary",
                           help="Everything in one file: report.md, findings (md + json), subdomains "
                                "(all/live/dead), ports, nuclei and compliance findings.")
        st.caption("Single archive — the report, the findings (Markdown + JSON) and every module's raw "
                   "output are all inside it.")
