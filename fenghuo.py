#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fenghuo.py  —  烽火 (Fēnghuǒ) :: CISA KEV beacon
================================================
A small, dependency-free early-warning tool. It pulls the CISA Known Exploited
Vulnerabilities (KEV) catalog, filters it against a watchlist YOU define — the
software that actually runs on YOUR machines — and writes one Markdown threat
note per new hit with a deterministic, evidence-bound assessment.

烽火 means "beacon fire": the signal towers that carried warnings along a wall.
That's the job here — not a scanner, a watcher.

WHAT IT IS
  - READ-ONLY INTEL. It fetches one public U.S. government JSON file over HTTPS
    and writes Markdown notes. It scans nothing, touches no host, needs no key,
    no account, no API token.
  - A KEV hit means the bug is being EXPLOITED IN THE WILD. It does NOT mean
    your asset is vulnerable. Every note ends with a verification step to run
    on the asset. This tool never claims patched/unpatched status.

HOW SCOPE WORKS
  Your watchlist lives in a Markdown "registry" file, under a `## KEV watchlist`
  heading, as a simple table (vendor | product | asset | exposure | patch path).
  The watchlist is the scope — it is read from the registry, never hard-coded
  here. A missing or malformed watchlist aborts the run with SCOPE UNCONFIRMED:
  a missing reading is never an all-clear. See `registry.example.md`.

OPERATOR PAUSE FLAG
  Add one line to the registry's YAML frontmatter to halt runs without touching
  your scheduler:
      fenghuo-pause: on         # 'off' or remove the line to resume
  It is read from the frontmatter ONLY, so a how-to example in the document body
  can never arm it, and it is fail-safe: anything missing, unreadable, malformed
  or ambiguous RUNS and says why. A beacon must never go dark on a typo.

DESIGN
  - Standard library only (urllib, json, hashlib, re, datetime, os).
  - ok-dict return shapes. Fail loud. Menu-return console.
  - TLS verification stays ON. Never bypassed.

USAGE
  python3 fenghuo.py                 # interactive console
  python3 fenghuo.py --auto          # headless run (cron/systemd); exit!=0 on error
  python3 fenghuo.py --pause-state    # print the current pause state and exit
  python3 fenghuo.py --vendors tesla # list live-feed vendors/products (tune rows)
  python3 fenghuo.py --cve CVE-2024-1234   # re-assess one CVE against your watchlist

CONFIG via environment (all optional; sane defaults below):
  FENGHUO_REGISTRY    path to your registry Markdown file
  FENGHUO_NOTES_DIR   where threat notes are written
  FENGHUO_STATE       JSON state file (seen CVEs, last run)
  FENGHUO_CADENCE     "weekly" (default) or "monthly" — drives the staleness alarm
  FENGHUO_AGENT       name stamped into note frontmatter (default "fenghuo")

MIT licensed. See LICENSE.
"""

import os
import re
import sys
import json
import hashlib
import urllib.request
import urllib.error
from datetime import datetime, timezone, date, timedelta


# ==========================================================================
# Config
# ==========================================================================

# The CISA KEV catalog. Single file: all current entries + catalogVersion +
# dateReleased. No key, no rate limit.
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")

# Where to read your watchlist registry from. Point it at your own Markdown file.
REGISTRY_PATH = (os.environ.get("FENGHUO_REGISTRY")
                 or os.path.expanduser("~/fenghuo/registry.md"))
_REGISTRY_FALLBACKS = [
    os.path.expanduser("~/.config/fenghuo/registry.md"),
    "registry.md",
    "registry.example.md",
]

# Where threat notes land. Created if missing.
NOTES_DIR = (os.environ.get("FENGHUO_NOTES_DIR")
             or os.path.expanduser("~/fenghuo/notes"))
_NOTES_FALLBACK = os.path.expanduser("./fenghuo_notes")

# State file (seen CVEs, last version, last success, last feed hash).
STATE_PATH = (os.environ.get("FENGHUO_STATE")
              or os.path.expanduser("~/fenghuo/state.json"))

# Pull cadence. Drives only the staleness alarm — the delta logic never misses a
# CVE between pulls, it just reports it later. KEV due dates commonly run ~3
# weeks; a monthly pull can surface a hit after its due date has already passed.
CADENCE = os.environ.get("FENGHUO_CADENCE") or "weekly"   # weekly | monthly
_STALE_DAYS = {"weekly": 8, "monthly": 35}

# Name stamped into note frontmatter.
AGENT = os.environ.get("FENGHUO_AGENT") or "fenghuo"

# Heartbeat / run-log note (one line per run). Lives alongside the notes.
LOG_NOTE_NAME = "烽火 Log.md"

# Backlog window on the very first (baseline) run.
BACKLOG_DAYS = 30

_TIMEOUT = 30
_HTTP_HEADERS = {"User-Agent": "fenghuo/2.0 (+owned-infra KEV beacon)",
                 "Accept": "application/json"}

# Required per-entry keys. `cwes` is intentionally optional (absent on old
# entries); its absence is NOT schema drift.
_REQUIRED_ENTRY_KEYS = (
    "cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded",
    "shortDescription", "requiredAction", "dueDate",
    "knownRansomwareCampaignUse", "notes",
)
_REQUIRED_TOP_KEYS = ("catalogVersion", "dateReleased", "count",
                      "vulnerabilities")


def _now():
    return datetime.now(timezone.utc).isoformat()


def _today():
    return date.today().isoformat()


# ==========================================================================
# Registry / watchlist parsing
# ==========================================================================

_WATCHLIST_HEADING = re.compile(r"^#{1,6}\s*KEV watchlist", re.I)
_PLACEHOLDER = re.compile(r"[<>]")   # rows with <placeholders> are skipped


def _find_registry():
    for p in [REGISTRY_PATH] + _REGISTRY_FALLBACKS:
        if p and os.path.isfile(p):
            return p
    return None


def _split_row(line):
    # "| a | b |" -> ["a", "b"]  (drop the empty edges).
    # Split on UNESCAPED pipes only: a markdown-escaped '\|' inside a cell
    # (e.g. a product regex "iOS\|iPadOS") is content, not a column break.
    s = line.strip().strip("|")
    cells = re.split(r"(?<!\\)\|", s)
    return [c.strip() for c in cells]


def parse_watchlist(path):
    """
    Read the first markdown table under the '## KEV watchlist' heading.

    Returns ok-dict:
        {"ok", "rows": [ {vendor, product, asset, exposure, patch_path,
                          product_re} ],
         "skipped": [ {row, reason} ], "source", "error"}
    A missing heading, missing table, or unreadable file is a hard fail:
    ok=False, which the caller turns into SCOPE UNCONFIRMED.
    """
    if not path:
        return {"ok": False, "rows": [], "skipped": [], "source": None,
                "error": "registry file not found (set FENGHUO_REGISTRY)"}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError as e:
        return {"ok": False, "rows": [], "skipped": [], "source": path,
                "error": f"cannot read registry: {type(e).__name__}"}

    # Locate the heading.
    start = None
    for i, ln in enumerate(lines):
        if _WATCHLIST_HEADING.match(ln):
            start = i + 1
            break
    if start is None:
        return {"ok": False, "rows": [], "skipped": [], "source": path,
                "error": "no '## KEV watchlist' heading in registry"}

    # Collect the first contiguous table (lines starting with '|').
    table = []
    seen_table = False
    for ln in lines[start:]:
        if ln.lstrip().startswith("|"):
            table.append(ln)
            seen_table = True
        elif seen_table:
            break   # table ended
    if len(table) < 3:
        return {"ok": False, "rows": [], "skipped": [], "source": path,
                "error": "watchlist table missing or has no data rows"}

    # Header -> column indices.
    header = [h.lower() for h in _split_row(table[0])]
    def _idx(name):
        for j, h in enumerate(header):
            if name in h:
                return j
        return None
    ci = {k: _idx(k) for k in ("vendor", "product", "asset",
                               "exposure", "patch")}
    if ci["vendor"] is None or ci["product"] is None:
        return {"ok": False, "rows": [], "skipped": [], "source": path,
                "error": "watchlist header missing vendor/product columns"}

    rows, skipped = [], []
    for ln in table[2:]:                    # skip header + separator
        cells = _split_row(ln)
        if not any(cells):
            continue
        def _get(key):
            j = ci[key]
            return cells[j] if (j is not None and j < len(cells)) else ""
        vendor = _get("vendor")
        product = _get("product")
        if not vendor or not product:
            continue
        if _PLACEHOLDER.search(vendor) or _PLACEHOLDER.search(product):
            skipped.append({"row": vendor + " / " + product,
                            "reason": "placeholder — fill in before it counts"})
            continue
        # Unescape markdown-escaped pipes so the alternation is a real regex.
        prod_pattern = product.replace("\\|", "|")
        try:
            prod_re = re.compile("(?:" + prod_pattern + ")", re.I)
        except re.error as e:
            skipped.append({"row": vendor + " / " + product,
                            "reason": f"bad product regex: {e}"})
            continue
        rows.append({
            "vendor": vendor,
            "product": product,
            "asset": _get("asset"),
            "exposure": _get("exposure"),
            "patch_path": _get("patch"),
            "product_re": prod_re,
        })

    if not rows:
        return {"ok": False, "rows": [], "skipped": skipped, "source": path,
                "error": "watchlist has no usable rows (all placeholders?)"}
    return {"ok": True, "rows": rows, "skipped": skipped, "source": path,
            "error": None}


# ==========================================================================
# Operator pause flag
# ==========================================================================
# Read ONLY from the registry's YAML frontmatter, so a how-to example written in
# the document BODY can never arm it. Fail-safe: missing / unreadable /
# malformed / ambiguous all RUN and say why. A beacon must not go dark on a typo.
#
# To pause, add ONE line to the top frontmatter of your registry file:
#     fenghuo-pause: on
# To resume: set it to `off`, or delete the line.

_FM_PAUSE = re.compile(r"^\s*fenghuo[-_ ]?pause\s*:\s*(\S+)", re.I)
_PAUSE_ON = {"on", "true", "yes", "paused", "1"}
_PAUSE_OFF = {"off", "false", "no", "running", "0"}


def _frontmatter(text):
    """Return the YAML frontmatter block (between the first two '---' fences),
    or '' if the file does not open with one / has no closing fence."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return ""
    body = []
    for ln in lines[1:]:
        if ln.strip() == "---":
            return "\n".join(body)
        body.append(ln)
    return ""


def check_pause(path):
    """Operator pause flag. Returns (paused: bool, note: str|None).
    Fail-safe = NOT paused: only an explicit, well-formed ON token pauses."""
    if not path:
        return False, None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            fm = _frontmatter(fh.read())
    except OSError as e:
        return False, (f"pause check couldn't read registry "
                       f"({type(e).__name__}) — running")
    val = None
    for ln in fm.splitlines():
        m = _FM_PAUSE.match(ln)
        if m:
            val = m.group(1).strip().strip("`\"'").lower()
            break
    if val is None:
        return False, None
    if val in _PAUSE_ON:
        return True, "PAUSED by operator (registry frontmatter flag set)"
    if val in _PAUSE_OFF:
        return False, None
    return False, f"pause flag malformed ({val!r}) — running anyway"


# ==========================================================================
# Feed fetch + validation
# ==========================================================================

def fetch_feed():
    """
    GET the KEV feed. Returns ok-dict:
        {"ok", "data", "sha256", "fetched_at", "error"}
    Any HTTP/TLS/timeout error is a loud FAILED, not an empty result.
    """
    req = urllib.request.Request(KEV_URL, headers=_HTTP_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        return {"ok": False, "data": None, "sha256": None,
                "fetched_at": _now(), "error": f"HTTP {e.code}"}
    except (urllib.error.URLError, OSError) as e:
        # URLError wraps TLS failures too — do NOT retry unverified.
        reason = getattr(e, "reason", e)
        return {"ok": False, "data": None, "sha256": None,
                "fetched_at": _now(), "error": f"{type(e).__name__}: {reason}"}

    sha = hashlib.sha256(raw).hexdigest()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        return {"ok": False, "data": None, "sha256": sha,
                "fetched_at": _now(), "error": f"JSON parse: {e}"}
    return {"ok": True, "data": data, "sha256": sha,
            "fetched_at": _now(), "error": None}


def validate_schema(data):
    """Guard against silent feed changes. Returns (ok, reason)."""
    if not isinstance(data, dict):
        return False, "top-level is not an object"
    for k in _REQUIRED_TOP_KEYS:
        if k not in data:
            return False, f"missing top-level key '{k}'"
    vulns = data["vulnerabilities"]
    if not isinstance(vulns, list):
        return False, "'vulnerabilities' is not a list"
    try:
        declared = int(data["count"])
    except (TypeError, ValueError):
        return False, "'count' is not an integer"
    if declared != len(vulns):
        return False, (f"count mismatch: header says {declared}, "
                       f"list has {len(vulns)}")
    # Spot-check entry shape on the first item (cheap, catches field renames).
    if vulns:
        missing = [k for k in _REQUIRED_ENTRY_KEYS if k not in vulns[0]]
        if missing:
            return False, "entry missing keys: " + ", ".join(missing)
    return True, "ok"


# ==========================================================================
# Matching + assessment
# ==========================================================================

def match_entry(entry, rows):
    """Return the first watchlist row this KEV entry matches, or None."""
    vendor = (entry.get("vendorProject") or "").strip().lower()
    product = entry.get("product") or ""
    for row in rows:
        if vendor != row["vendor"].strip().lower():
            continue
        if row["product_re"].search(product):
            return row
    return None


def assess(entry, row):
    """
    Deterministic, evidence-bound severity. Rests on the matched row's
    exposure + patch path, never on a guess.

    Returns dict: {priority, ransomware, mitigation_only, reason, verify_step}
    """
    exposure = (row.get("exposure") or "").lower()
    patch = (row.get("patch_path") or "").lower()
    product_l = (entry.get("product") or "").lower()
    ransomware = (entry.get("knownRansomwareCampaignUse") or "").strip().lower() \
        == "known"
    broad = "multiple products" in product_l

    internet = ("internet-facing" in exposure) or ("every network" in exposure)
    nearby = any(t in exposure for t in ("lan", "tunnel", "outbound"))

    if ransomware or internet:
        prio, reason = "P1", []
        if ransomware:
            reason.append("ransomware-linked in the wild")
        if internet:
            reason.append(f"exposure: {row.get('exposure')}")
        reason = "Act today — " + "; ".join(reason) + "."
    elif nearby:
        prio = "P2"
        reason = f"This week — exposure: {row.get('exposure')}."
    else:
        prio = "P3"
        reason = ("Verify and watch — " +
                  ("broad product match (Multiple Products)"
                   if broad else f"local exposure: {row.get('exposure')}") + ".")

    mitigation_only = ("not operator-controlled" in patch) or \
                      ("vendor push" in patch)

    verify_step = ("Identify the installed version on the affected asset and "
                   "compare against the advisory's fixed version. Snapshot/back "
                   "up before any reboot-risk upgrade.")
    return {"priority": prio, "ransomware": ransomware,
            "mitigation_only": mitigation_only, "reason": reason,
            "verify_step": verify_step}


# ==========================================================================
# State
# ==========================================================================

def load_state():
    if not os.path.isfile(STATE_PATH):
        return {"seen": {}, "last_catalog_version": None,
                "last_success_utc": None, "last_feed_sha256": None,
                "last_run_summary": None}
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as fh:
            st = json.load(fh)
    except (OSError, ValueError):
        # Corrupt state is not "clean" — surface it; caller treats as first run
        # but flags it.
        return {"seen": {}, "last_catalog_version": None,
                "last_success_utc": None, "last_feed_sha256": None,
                "last_run_summary": None, "_corrupt": True}
    st.setdefault("seen", {})
    return st


def save_state(st):
    st.pop("_corrupt", None)
    os.makedirs(os.path.dirname(STATE_PATH) or ".", exist_ok=True)
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(st, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, STATE_PATH)   # atomic


def _entry_fingerprint(entry):
    """What we watch for drift on a seen CVE."""
    return {
        "dueDate": entry.get("dueDate", ""),
        "ransomware": (entry.get("knownRansomwareCampaignUse") or "").strip(),
        "notes_hash": hashlib.sha256(
            (entry.get("notes") or "").encode("utf-8")).hexdigest()[:16],
    }


def _staleness(st):
    """(is_stale, days_since) against the configured cadence."""
    last = st.get("last_success_utc")
    if not last:
        return False, None
    try:
        then = datetime.fromisoformat(last)
    except ValueError:
        return False, None
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    days = (datetime.now(timezone.utc) - then).total_seconds() / 86400.0
    return days > _STALE_DAYS.get(CADENCE, 8), round(days, 1)


# ==========================================================================
# Note rendering
# ==========================================================================

def _safe_filename(cve, product):
    base = f"{cve} {product}"
    base = re.sub(r"[\\/:|<>?*\"]+", " ", base)
    base = re.sub(r"\s+", " ", base).strip()
    return base[:120] + ".md"


def _vendor_slug(vendor):
    return re.sub(r"[^a-z0-9]+", "-", vendor.lower()).strip("-") or "vendor"


def render_frontmatter(entry, row, a):
    tags = f"[kev, {_vendor_slug(row['vendor'])}]"
    lines = [
        "---",
        "type: threat",
        f"agent: {AGENT}",
        "status: open",
        f"updated: {_today()}",
        f"tags: {tags}",
        f"priority: {a['priority']}",
        f"cve: {entry.get('cveID','')}",
        f"due: {entry.get('dueDate','') or 'n/a'}",
        f"ransomware: {'true' if a['ransomware'] else 'false'}",
        "---",
    ]
    return "\n".join(lines)


def render_note_body(entry, row, a):
    cve = entry.get("cveID", "")
    refs = [u.strip() for u in (entry.get("notes") or "").split(";")
            if u.strip().startswith("http")]
    ref_block = ("\n".join(f"- {u}" for u in refs)) if refs else "- (none listed in KEV)"
    cwes = ", ".join(entry.get("cwes", []) or []) or "n/a"

    body = f"""# {cve} — {entry.get('product','')}

> **{a['priority']} · {a['reason']}**
> KEV proves this is exploited in the wild. It does **not** prove this asset is
> vulnerable. Confirm on the asset before acting — see Verify below.

**Vulnerability.** {entry.get('vulnerabilityName','')}
{entry.get('shortDescription','')}

**KEV facts**
- Vendor / product: {entry.get('vendorProject','')} / {entry.get('product','')}
- Added to KEV: {entry.get('dateAdded','')}
- Federal due date: {entry.get('dueDate','') or 'n/a'}
- Ransomware campaign use: {entry.get('knownRansomwareCampaignUse','')}
- CWEs: {cwes}

**Matched asset (from your registry watchlist)**
- Asset: {row.get('asset','')}
- Exposure: {row.get('exposure','')}
- Patch path: {row.get('patch_path','')}{'  — **mitigation-only; patch not operator-controlled**' if a['mitigation_only'] else ''}

**Assessment.** {a['reason']}

**Required action (CISA).** {entry.get('requiredAction','')}

**Verify (do this before you believe it applies).** {a['verify_step']}

**Advisories / references**
{ref_block}

---
log: [[烽火 Log]]
"""
    return body


def render_note(entry, row, a):
    return render_frontmatter(entry, row, a) + "\n\n" + render_note_body(entry, row, a)


# ==========================================================================
# Note / log I/O
# ==========================================================================

def _ensure_notes_dir():
    """Return (dir, used_fallback). Never fails silently."""
    for d in (NOTES_DIR, _NOTES_FALLBACK):
        try:
            os.makedirs(d, exist_ok=True)
            probe = os.path.join(d, ".fenghuo_write_test")
            with open(probe, "w") as fh:
                fh.write("ok")
            os.remove(probe)
            return d, (d == _NOTES_FALLBACK)
        except OSError:
            continue
    return None, False


def write_note(out_dir, entry, row, a):
    fn = _safe_filename(entry.get("cveID", ""), entry.get("product", ""))
    path = os.path.join(out_dir, fn)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_note(entry, row, a))
    return path


def find_note(out_dir, cve):
    try:
        for fn in os.listdir(out_dir):
            if fn.startswith(cve + " ") and fn.endswith(".md"):
                return os.path.join(out_dir, fn)
    except OSError:
        pass
    return None


def append_amendment(out_dir, entry, row, a, changed):
    """A seen CVE whose dueDate/ransomware/notes changed — append, not rewrite."""
    path = find_note(out_dir, entry.get("cveID", ""))
    if not path:                       # note gone — recreate it instead
        return write_note(out_dir, entry, row, a), True
    stamp = _today()
    block = (f"\n\n---\n**Amended {stamp}** — KEV entry changed: "
             f"{', '.join(changed)}. Now: due {entry.get('dueDate','') or 'n/a'}, "
             f"ransomware {entry.get('knownRansomwareCampaignUse','')}. "
             f"Re-assessment: {a['priority']} — {a['reason']}\n")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(block)
    return path, False


def write_backlog(out_dir, hits, catalog_version):
    """Single summary note on the baseline run — not hundreds of per-hit notes."""
    cutoff = (date.today() - timedelta(days=BACKLOG_DAYS)).isoformat()
    recent = [h for h in hits if (h["entry"].get("dateAdded", "") >= cutoff)]
    fn = f"KEV Backlog {_today()}.md"
    path = os.path.join(out_dir, fn)
    lines = [
        "---", "type: threat-summary", f"agent: {AGENT}", "status: open",
        f"updated: {_today()}", "tags: [kev, backlog]", "---", "",
        f"# KEV Backlog — baseline {_today()}", "",
        f"> Baseline run. {len(hits)} current watchlist matches recorded as "
        f"seen; the {len(recent)} added in the last {BACKLOG_DAYS} days are "
        f"listed below. catalogVersion {catalog_version}.",
        "> KEV = exploited in the wild, not proof your asset is vulnerable.",
        "",
        "| CVE | Product | Asset | Added | Due | Prio | Ransomware |",
        "|---|---|---|---|---|---|---|",
    ]
    for h in sorted(recent, key=lambda x: x["entry"].get("dateAdded", ""),
                    reverse=True):
        e, a = h["entry"], h["assess"]
        lines.append(
            f"| {e.get('cveID','')} | {e.get('product','')} | "
            f"{h['row'].get('asset','')} | {e.get('dateAdded','')} | "
            f"{e.get('dueDate','') or 'n/a'} | {a['priority']} | "
            f"{'YES' if a['ransomware'] else 'no'} |")
    lines += ["", "---", "log: [[烽火 Log]]", ""]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


def write_heartbeat(out_dir, status, counts, catalog_version, sha, stale_note):
    """One line per run. A reading, even when nothing fired."""
    path = os.path.join(out_dir, LOG_NOTE_NAME)
    if not os.path.isfile(path):
        header = ("---\ntype: log\n" + f"agent: {AGENT}\n" + "status: open\n"
                  f"updated: {_today()}\ntags: [kev, log]\n---\n\n"
                  "# 烽火 Log\n\n> One line per run.\n\n## Runs\n")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(header)
    line = (f"- {_now()} | {status} | {counts} | catalogVersion "
            f"{catalog_version} | sha256 {str(sha)[:12]}"
            f"{' | ' + stale_note if stale_note else ''}\n")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line)
    return path


# ==========================================================================
# The run
# ==========================================================================

def run_pull():
    """
    Full pull → match → write. Returns ok-dict with everything the console and
    --auto need. Fails loud at every gate; never writes on a bad reading.
    """
    started = _now()
    st = load_state()
    first_run = not st.get("seen")
    stale, days = _staleness(st)
    stale_note = (f"STALE: last success {days}d ago (>{_STALE_DAYS[CADENCE]}d "
                  f"for {CADENCE})") if stale else None

    # --- Pause gate: operator halts runs via the registry frontmatter flag. ---
    reg = _find_registry()
    paused, pause_note = check_pause(reg)
    if paused:
        out_dir, _ = _ensure_notes_dir()
        if out_dir:
            write_heartbeat(out_dir, "PAUSED by operator",
                            "run skipped — registry pause flag set",
                            "n/a", "n/a", stale_note)
        return {"ok": True, "phase": "paused", "paused": True,
                "pause_note": pause_note, "stale_note": stale_note,
                "counts": "PAUSED by operator (run skipped)",
                "notes_dir": out_dir, "started": started, "error": None}
    if pause_note:                      # malformed flag: ran anyway, flag it loud
        stale_note = " | ".join(x for x in (stale_note, pause_note) if x)

    # --- Scope gate: watchlist must load, or we do not run. ---
    wl = parse_watchlist(reg)
    if not wl["ok"]:
        out_dir, _ = _ensure_notes_dir()
        if out_dir:
            write_heartbeat(out_dir, "SCOPE UNCONFIRMED", wl["error"],
                            "?", "?", stale_note)
        return {"ok": False, "phase": "scope",
                "error": "SCOPE UNCONFIRMED: " + str(wl["error"]),
                "skipped_rows": wl.get("skipped", []), "started": started}

    # --- Fetch. ---
    feed = fetch_feed()
    if not feed["ok"]:
        out_dir, _ = _ensure_notes_dir()
        if out_dir:
            write_heartbeat(out_dir, "FAILED", feed["error"], "?",
                            feed.get("sha256") or "?", stale_note)
        return {"ok": False, "phase": "fetch",
                "error": "FETCH FAILED: " + str(feed["error"]),
                "started": started}

    data = feed["data"]
    ok_schema, why = validate_schema(data)
    if not ok_schema:
        out_dir, _ = _ensure_notes_dir()
        if out_dir:
            write_heartbeat(out_dir, "SCHEMA DRIFT", why, "?",
                            feed["sha256"], stale_note)
        return {"ok": False, "phase": "schema",
                "error": "SCHEMA DRIFT (wrote nothing): " + why,
                "started": started}

    catalog_version = data.get("catalogVersion", "?")
    vulns = data["vulnerabilities"]

    # --- Match everything on the watchlist. ---
    hits = []
    for e in vulns:
        row = match_entry(e, wl["rows"])
        if row:
            hits.append({"entry": e, "row": row, "assess": assess(e, row)})

    out_dir, used_fallback = _ensure_notes_dir()
    if not out_dir:
        return {"ok": False, "phase": "notes",
                "error": "Cannot write notes to NOTES_DIR or fallback.",
                "started": started}

    written, amended, new_cves = [], [], []
    backlog_path = None

    if first_run:
        # Baseline: record all as seen, write ONE backlog note.
        for h in hits:
            st["seen"][h["entry"]["cveID"]] = _entry_fingerprint(h["entry"])
        backlog_path = write_backlog(out_dir, hits, catalog_version)
    else:
        for h in hits:
            cve = h["entry"]["cveID"]
            fp = _entry_fingerprint(h["entry"])
            if cve not in st["seen"]:
                written.append(write_note(out_dir, h["entry"], h["row"],
                                          h["assess"]))
                new_cves.append(cve)
                st["seen"][cve] = fp
            else:
                old = st["seen"][cve]
                changed = [k for k in ("dueDate", "ransomware", "notes_hash")
                           if old.get(k) != fp.get(k)]
                if changed:
                    append_amendment(out_dir, h["entry"], h["row"],
                                     h["assess"], changed)
                    amended.append((cve, changed))
                    st["seen"][cve] = fp

    # --- Commit state + heartbeat. ---
    st["last_catalog_version"] = catalog_version
    st["last_success_utc"] = _now()
    st["last_feed_sha256"] = feed["sha256"]
    counts = (f"{len(new_cves)} new / {len(amended)} amended / "
              f"{len(hits)} matched / {len(wl['rows'])} rows watched")
    if first_run:
        counts = (f"BASELINE: {len(hits)} matched recorded seen / "
                  f"{len(wl['rows'])} rows watched")
    st["last_run_summary"] = {"at": st["last_success_utc"], "counts": counts,
                              "catalog_version": catalog_version}
    save_state(st)

    status = "BASELINE" if first_run else ("HITS" if new_cves or amended
                                           else "OK (0 new)")
    write_heartbeat(out_dir, status, counts, catalog_version,
                    feed["sha256"], stale_note)

    return {"ok": True, "phase": "done", "first_run": first_run,
            "catalog_version": catalog_version, "total_vulns": len(vulns),
            "matched": len(hits), "new_cves": new_cves, "amended": amended,
            "written": written, "backlog_path": backlog_path,
            "notes_dir": out_dir, "used_fallback": used_fallback,
            "skipped_rows": wl.get("skipped", []), "stale_note": stale_note,
            "counts": counts, "started": started, "error": None}


# ==========================================================================
# Human formatting
# ==========================================================================

def format_pull(r):
    if r.get("paused"):
        lines = ["# 烽火 — PAUSED by operator (run skipped)"]
        if r.get("pause_note"):
            lines.append(r["pause_note"])
        if r.get("stale_note"):
            lines.append(f"**{r['stale_note']}**")
        return "\n".join(lines)

    if not r["ok"]:
        lines = [f"# 烽火 — {r['error']}"]
        if r.get("skipped_rows"):
            lines.append("Skipped watchlist rows:")
            for s in r["skipped_rows"]:
                lines.append(f"  - {s['row']}: {s['reason']}")
        return "\n".join(lines)

    lines = ["# 烽火 — pull complete"]
    if r.get("stale_note"):
        lines.append(f"**{r['stale_note']}**")
    lines.append(f"catalogVersion {r['catalog_version']} · "
                 f"{r['total_vulns']} CVEs in feed · {r['matched']} matched "
                 f"the watchlist")
    lines.append(r["counts"])
    if r.get("used_fallback"):
        lines.append(f"!! Notes went to FALLBACK dir: {r['notes_dir']}")
    else:
        lines.append(f"Notes dir: {r['notes_dir']}")
    if r["first_run"]:
        lines.append(f"Baseline note: {os.path.basename(r['backlog_path'])}")
    if r["new_cves"]:
        lines.append("New notes:")
        for c in r["new_cves"]:
            lines.append(f"  + {c}")
    if r["amended"]:
        lines.append("Amended:")
        for c, ch in r["amended"]:
            lines.append(f"  ~ {c} ({', '.join(ch)})")
    if r.get("skipped_rows"):
        lines.append("Skipped watchlist rows:")
        for s in r["skipped_rows"]:
            lines.append(f"  - {s['row']}: {s['reason']}")
    if not r["new_cves"] and not r["amended"] and not r["first_run"]:
        lines.append("No new hits. A reading, not silence.")
    return "\n".join(lines)


def format_vendors(data, substr):
    """Distinct vendor/product values in the live feed — for tuning rows."""
    vulns = data.get("vulnerabilities", [])
    pairs = {}
    s = (substr or "").lower()
    for e in vulns:
        v = e.get("vendorProject", "")
        p = e.get("product", "")
        if s and s not in v.lower() and s not in p.lower():
            continue
        pairs.setdefault(v, set()).add(p)
    lines = ["# Live feed vendors/products"
             + (f" matching '{substr}'" if substr else "") +
             f" ({sum(len(x) for x in pairs.values())} products, "
             f"{len(pairs)} vendors)"]
    for v in sorted(pairs, key=str.lower):
        lines.append(f"\n{v}")
        for p in sorted(pairs[v], key=str.lower):
            lines.append(f"  · {p}")
    return "\n".join(lines)


def format_reassess(data, rows, cve):
    cve = cve.strip().upper()
    for e in data.get("vulnerabilities", []):
        if (e.get("cveID") or "").upper() == cve:
            row = match_entry(e, rows)
            if not row:
                return (f"{cve} is in KEV but matches NO watchlist row — "
                        f"out of watched scope.\n"
                        f"  vendor/product: {e.get('vendorProject')} / "
                        f"{e.get('product')}")
            a = assess(e, row)
            return render_note(e, row, a)
    return f"{cve} not found in the current KEV feed."


# ==========================================================================
# Console (menu-return) + headless
# ==========================================================================

def _console():
    while True:
        print("\n=== 烽火 Fēnghuǒ :: CISA KEV beacon ===")
        reg = _find_registry()
        paused, pause_note = check_pause(reg)
        print(f"  cadence={CADENCE}  registry={reg or 'NOT FOUND'}  "
              f"state={'PAUSED' if paused else 'running'}")
        if pause_note and not paused:
            print(f"  !! {pause_note}")
        print("  1) Pull now (match + write notes)")
        print("  2) Show last run")
        print("  3) Vendor-string lookup (tune the watchlist)")
        print("  4) Re-assess one CVE")
        print("  5) Pause state (check the operator flag)")
        print("  0) Quit")
        choice = input("> ").strip()

        if choice == "0":
            return
        elif choice == "1":
            print("\nPulling KEV feed...")
            print("\n" + format_pull(run_pull()))
        elif choice == "2":
            st = load_state()
            s = st.get("last_run_summary")
            stale, days = _staleness(st)
            if not s:
                print("\nNo recorded run yet.")
            else:
                print(f"\nLast run: {s['at']}\n  {s['counts']}"
                      f"\n  catalogVersion {s['catalog_version']}")
                if stale:
                    print(f"  ** STALE: {days}d since last success "
                          f"(>{_STALE_DAYS[CADENCE]}d for {CADENCE}) **")
        elif choice == "3":
            sub = input("vendor/product substring (blank = all): ").strip()
            feed = fetch_feed()
            if not feed["ok"]:
                print("\nFETCH FAILED: " + str(feed["error"]))
            else:
                print("\n" + format_vendors(feed["data"], sub))
        elif choice == "4":
            cve = input("CVE id (e.g. CVE-2024-1234): ").strip()
            if not cve:
                continue
            wl = parse_watchlist(_find_registry())
            if not wl["ok"]:
                print("\nSCOPE UNCONFIRMED: " + str(wl["error"]))
                continue
            feed = fetch_feed()
            if not feed["ok"]:
                print("\nFETCH FAILED: " + str(feed["error"]))
                continue
            print("\n" + format_reassess(feed["data"], wl["rows"], cve))
        elif choice == "5":
            reg = _find_registry()
            paused, note = check_pause(reg)
            print(f"\nRegistry: {reg or 'NOT FOUND'}")
            print(f"Pause flag: {'PAUSED' if paused else 'running'}")
            if note:
                print(f"  {note}")
            print("  Set `fenghuo-pause: on` in the registry frontmatter to "
                  "pause; `off` or remove to resume.")
        else:
            print("  ?")


def run_auto():
    """Headless run. Prints a one-line result; exit code != 0 on any failure so
    cron/systemd can tell. A PAUSED run is ok=True → exit 0."""
    r = run_pull()
    print(format_pull(r))
    return 0 if r["ok"] else 1


def main():
    argv = sys.argv[1:]
    if "--auto" in argv:
        sys.exit(run_auto())
    if "--pause-state" in argv:
        reg = _find_registry()
        paused, note = check_pause(reg)
        print(f"registry={reg or 'NOT FOUND'}  "
              f"state={'PAUSED' if paused else 'running'}"
              + (f"  ({note})" if note else ""))
        return
    if "--vendors" in argv:
        i = argv.index("--vendors")
        sub = argv[i + 1] if i + 1 < len(argv) else ""
        feed = fetch_feed()
        print(format_vendors(feed["data"], sub) if feed["ok"]
              else "FETCH FAILED: " + str(feed["error"]))
        return
    if "--cve" in argv:
        i = argv.index("--cve")
        cve = argv[i + 1] if i + 1 < len(argv) else ""
        wl = parse_watchlist(_find_registry())
        if not wl["ok"]:
            print("SCOPE UNCONFIRMED: " + str(wl["error"]))
            return
        feed = fetch_feed()
        print(format_reassess(feed["data"], wl["rows"], cve) if feed["ok"]
              else "FETCH FAILED: " + str(feed["error"]))
        return
    _console()


if __name__ == "__main__":
    main()
