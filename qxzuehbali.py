"""
GitHub Secret Hunter — Flask Dashboard
Port 5555 | Dark theme | No JS frameworks
"""

import json
import re
from pathlib import Path
from datetime import datetime
from math import ceil

from flask import Flask, request, jsonify, Response

app = Flask(__name__)

ROOT = Path(__file__).resolve().parent
WATCHER_STATE = ROOT / "output" / "watcher_state.json"
MERGED_FINDINGS = ROOT / "output" / "merged_findings.json"
ALERTS_LOG = ROOT / "logs" / "watcher_alerts.log"

DARK_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #1a1a2e; color: #eee; font-family: 'Segoe UI', monospace; font-size: 14px; }
a { color: #7eb8f7; text-decoration: none; }
a:hover { text-decoration: underline; }
h1 { font-size: 1.6rem; font-weight: 700; }
h2 { font-size: 1.1rem; font-weight: 600; margin-bottom: 10px; color: #aac4f7; }
.header { background: #0f3460; padding: 18px 32px; display: flex; justify-content: space-between; align-items: center; }
.header .ts { font-size: 0.85rem; color: #aac4f7; }
.container { max-width: 1400px; margin: 0 auto; padding: 24px 32px; }
.stats-row { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 28px; }
.stat-card { background: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 16px 24px; min-width: 160px; flex: 1; }
.stat-card .val { font-size: 2rem; font-weight: 700; color: #7eb8f7; }
.stat-card .lbl { font-size: 0.78rem; color: #888; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
.section { background: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 20px 24px; margin-bottom: 24px; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th { background: #0f3460; color: #aac4f7; text-align: left; padding: 8px 10px; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.5px; }
td { padding: 7px 10px; border-bottom: 1px solid #1a1a2e; vertical-align: top; word-break: break-all; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #1f2d4a; }
.sev-critical { color: #e94560; font-weight: 700; }
.sev-high { color: #f5a623; font-weight: 600; }
.sev-medium { color: #ffe080; }
.sev-low { color: #7fe880; }
.bar-row { display: flex; align-items: center; gap: 10px; padding: 4px 0; font-size: 0.82rem; }
.bar-label { min-width: 220px; color: #ccc; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bar-fill { color: #7eb8f7; letter-spacing: -1px; }
.bar-count { color: #888; min-width: 40px; text-align: right; }
.no-data { color: #555; font-style: italic; padding: 16px 0; }
.pagination { margin-top: 16px; display: flex; gap: 8px; align-items: center; }
.pagination a { background: #0f3460; padding: 5px 12px; border-radius: 4px; color: #eee; }
.pagination .cur { background: #e94560; padding: 5px 12px; border-radius: 4px; }
.monospace { font-family: 'Courier New', monospace; font-size: 0.8rem; }
"""


# ─── Data helpers ────────────────────────────────────────────────────────────

def load_json(path: Path):
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def read_log_lines(path: Path, n: int = 200):
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            return f.readlines()
    except Exception:
        return []


def severity_class(sev: str) -> str:
    s = (sev or "").lower()
    if s == "critical":
        return "sev-critical"
    if s == "high":
        return "sev-high"
    if s == "medium":
        return "sev-medium"
    return "sev-low"


def parse_alerts(lines: list[str]) -> list[dict]:
    """
    Parse blocks like:
    [ALERT 2026-01-01T12:00:00] NEW FINDING -- CRITICAL openai_key
      Repo:  owner/repo (* 123, pushed 2026-01-01)
      File:  path/to/file.py line 42
      Match: sk-proj-abc...xyz789
      URL:   https://github.com/...
    """
    alerts = []
    current = {}
    header_re = re.compile(
        r"\[ALERT\s+([\dT:\-\.]+)\]\s+NEW FINDING\s+--\s+(\w+)\s+([\w_]+)"
    )
    repo_re = re.compile(r"Repo:\s+(.+)")
    match_re = re.compile(r"Match:\s+(.+)")
    url_re = re.compile(r"URL:\s+(https?://\S+)")

    for line in lines:
        line = line.rstrip()
        m = header_re.search(line)
        if m:
            if current:
                alerts.append(current)
            current = {
                "timestamp": m.group(1),
                "severity": m.group(2),
                "pattern": m.group(3),
                "repo": "",
                "match": "",
                "url": "",
            }
            continue
        if current:
            rm = repo_re.search(line)
            if rm:
                current["repo"] = rm.group(1).strip()
                continue
            mm = match_re.search(line)
            if mm:
                current["match"] = mm.group(1).strip()
                continue
            um = url_re.search(line)
            if um:
                current["url"] = um.group(1).strip()

    if current:
        alerts.append(current)

    return alerts


def get_state():
    return load_json(WATCHER_STATE) or {}


def get_findings():
    data = load_json(MERGED_FINDINGS)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "findings" in data:
        return data["findings"]
    return []


def findings_by_pattern(findings: list) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for f in findings:
        name = f.get("pattern_name") or f.get("pattern") or "unknown"
        counts[name] = counts.get(name, 0) + 1
    return sorted(counts.items(), key=lambda x: x[1], reverse=True)


def critical_findings(findings: list, n: int = 10) -> list:
    crits = [f for f in findings if (f.get("severity") or "").upper() == "CRITICAL"]
    return crits[-n:][::-1]  # last N, newest first


def mask(s: str) -> str:
    if not s:
        return ""
    s = str(s)
    if len(s) <= 10:
        return s[:3] + "***"
    return s[:6] + "..." + s[-4:]


def bar_chart_html(items: list[tuple[str, int]], max_width: int = 40) -> str:
    if not items:
        return '<div class="no-data">No data</div>'
    max_val = max(c for _, c in items) or 1
    rows = []
    for name, count in items[:50]:
        filled = int((count / max_val) * max_width)
        bar = "#" * filled
        rows.append(
            f'<div class="bar-row">'
            f'<span class="bar-label" title="{name}">{name}</span>'
            f'<span class="bar-fill">{bar}</span>'
            f'<span class="bar-count">{count}</span>'
            f"</div>"
        )
    return "\n".join(rows)


def rotation_slots(state: dict) -> list[dict]:
    rotation = state.get("rotation", [])
    if isinstance(rotation, list):
        return rotation
    return []


# ─── HTML helpers ─────────────────────────────────────────────────────────────

def page_wrap(title: str, body: str, refresh: int = 60) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta http-equiv="refresh" content="{refresh}"/>
<title>{title}</title>
<style>{DARK_CSS}</style>
</head>
<body>
<div class="header">
  <h1>GitHub Secret Hunter Dashboard</h1>
  <span class="ts">{now} &nbsp;|&nbsp; auto-refresh {refresh}s &nbsp;|&nbsp;
    <a href="/">Home</a> &nbsp;
    <a href="/findings">Findings</a> &nbsp;
    <a href="/api/stats">API</a>
  </span>
</div>
<div class="container">
{body}
</div>
</body>
</html>"""


def sev_cell(sev: str) -> str:
    cls = severity_class(sev)
    return f'<span class="{cls}">{sev or "?"}</span>'


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    state = get_state()
    findings = get_findings()
    log_lines = read_log_lines(ALERTS_LOG)
    alerts = parse_alerts(log_lines)

    # ── Stats row ──
    total_cycles = state.get("total_cycles", state.get("cycles", "N/A"))
    total_findings = state.get("total_findings", len(findings))
    total_new = state.get("total_new", state.get("new_findings", "N/A"))
    unique_seen = state.get("unique_seen", state.get("seen_count", "N/A"))
    token_pool = state.get("token_pool_size", state.get("tokens_count", "N/A"))

    def sc(v, lbl):
        return f'<div class="stat-card"><div class="val">{v}</div><div class="lbl">{lbl}</div></div>'

    stats_html = (
        '<div class="stats-row">'
        + sc(total_cycles, "Total Cycles")
        + sc(total_findings, "Total Findings")
        + sc(total_new, "Total New")
        + sc(unique_seen, "Unique Seen")
        + sc(token_pool, "Token Pool Size")
        + "</div>"
    )

    # ── Recent alerts table (last 20) ──
    last_alerts = alerts[-20:][::-1]
    if last_alerts:
        rows = ""
        for a in last_alerts:
            repo_link = (
                f'<a href="{a["url"]}" target="_blank">{a["repo"]}</a>'
                if a.get("url")
                else a.get("repo", "")
            )
            rows += (
                f"<tr>"
                f'<td class="monospace">{a["timestamp"]}</td>'
                f"<td>{sev_cell(a['severity'])}</td>"
                f"<td>{a['pattern']}</td>"
                f"<td>{repo_link}</td>"
                f'<td class="monospace">{a["match"]}</td>'
                f"</tr>"
            )
        alerts_table = f"""
<table>
<thead><tr>
  <th>Timestamp</th><th>Severity</th><th>Pattern</th><th>Repo</th><th>Match</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>"""
    else:
        alerts_table = '<div class="no-data">No alerts found in log.</div>'

    alerts_section = f'<div class="section"><h2>Recent Alerts (last 20)</h2>{alerts_table}</div>'

    # ── Pattern bar chart ──
    by_pattern = findings_by_pattern(findings)
    chart_html = f'<div class="section"><h2>Findings by Pattern</h2>{bar_chart_html(by_pattern)}</div>'

    # ── Last 10 CRITICAL findings ──
    crits = critical_findings(findings, 10)
    if crits:
        rows = ""
        for f_ in crits:
            repo = f_.get("repo", f_.get("repository", ""))
            url = f_.get("url", f_.get("html_url", ""))
            repo_cell = f'<a href="{url}" target="_blank">{repo}</a>' if url else repo
            pattern = f_.get("pattern_name") or f_.get("pattern") or ""
            raw = f_.get("match", f_.get("secret", f_.get("value", "")))
            score = f_.get("score", "")
            rows += (
                f"<tr>"
                f"<td>{score}</td>"
                f"<td>{sev_cell('CRITICAL')}</td>"
                f"<td>{pattern}</td>"
                f"<td>{repo_cell}</td>"
                f'<td class="monospace">{mask(raw)}</td>'
                f"</tr>"
            )
        crits_table = f"""
<table>
<thead><tr>
  <th>Score</th><th>Severity</th><th>Pattern</th><th>Repo</th><th>Masked Match</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>"""
    else:
        crits_table = '<div class="no-data">No CRITICAL findings.</div>'

    crits_section = f'<div class="section"><h2>Last 10 CRITICAL Findings</h2>{crits_table}</div>'

    # ── Rotation schedule ──
    slots = rotation_slots(state)
    if slots:
        rows = ""
        for slot in slots:
            if isinstance(slot, dict):
                label = slot.get("label", slot.get("name", ""))
                token = slot.get("token", slot.get("key", ""))
                every = slot.get("every", slot.get("interval", ""))
                last = slot.get("last_run", "")
                rows += (
                    f"<tr>"
                    f"<td>{label}</td>"
                    f'<td class="monospace">{mask(token)}</td>'
                    f"<td>{every}</td>"
                    f"<td>{last}</td>"
                    f"</tr>"
                )
            else:
                rows += f"<tr><td colspan='4'>{slot}</td></tr>"
        rot_table = f"""
<table>
<thead><tr>
  <th>Label</th><th>Token</th><th>Interval</th><th>Last Run</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>"""
    else:
        # Fallback: show raw state keys that look like rotation
        hunt_rotation = state.get("HUNT_ROTATION", state.get("hunt_rotation", []))
        if hunt_rotation:
            rows = "".join(
                f"<tr><td colspan='4' class='monospace'>{slot}</td></tr>"
                for slot in hunt_rotation
            )
            rot_table = f"<table><tbody>{rows}</tbody></table>"
        else:
            rot_table = '<div class="no-data">No rotation schedule found in state.</div>'

    rot_section = f'<div class="section"><h2>Rotation Schedule</h2>{rot_table}</div>'

    body = stats_html + alerts_section + chart_html + crits_section + rot_section
    return page_wrap("Secret Hunter Dashboard", body)


@app.route("/api/stats")
def api_stats():
    state = get_state()
    findings = get_findings()
    by_pattern = findings_by_pattern(findings)
    sev_counts: dict[str, int] = {}
    for f_ in findings:
        s = (f_.get("severity") or "unknown").upper()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    payload = {
        "generated_at": datetime.now().isoformat(),
        "state": state,
        "findings_total": len(findings),
        "findings_by_severity": sev_counts,
        "findings_by_pattern": dict(by_pattern),
    }
    return jsonify(payload)


@app.route("/findings")
def findings_page():
    findings = get_findings()
    page = max(1, int(request.args.get("page", 1)))
    per_page = 100
    total = len(findings)
    total_pages = max(1, ceil(total / per_page))
    page = min(page, total_pages)

    start = (page - 1) * per_page
    end = start + per_page
    page_items = findings[start:end]

    if page_items:
        rows = ""
        for f_ in page_items:
            repo = f_.get("repo", f_.get("repository", ""))
            url = f_.get("url", f_.get("html_url", ""))
            repo_cell = f'<a href="{url}" target="_blank">{repo}</a>' if url else repo
            pattern = f_.get("pattern_name") or f_.get("pattern") or ""
            raw = f_.get("match", f_.get("secret", f_.get("value", "")))
            score = f_.get("score", "")
            sev = f_.get("severity", "")
            source = f_.get("source", f_.get("source_token", ""))
            rows += (
                f"<tr>"
                f"<td>{score}</td>"
                f"<td>{sev_cell(sev)}</td>"
                f"<td>{pattern}</td>"
                f"<td>{repo_cell}</td>"
                f'<td class="monospace">{mask(raw)}</td>'
                f"<td>{source}</td>"
                f"</tr>"
            )
        table = f"""
<table>
<thead><tr>
  <th>Score</th><th>Severity</th><th>Pattern</th><th>Repo</th><th>Masked Match</th><th>Source</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>"""
    else:
        table = '<div class="no-data">No findings yet.</div>'

    # Pagination links
    pag = '<div class="pagination">'
    if page > 1:
        pag += f'<a href="/findings?page={page-1}">&#8592; Prev</a>'
    pag += f'<span class="cur">Page {page} / {total_pages}</span>'
    if page < total_pages:
        pag += f'<a href="/findings?page={page+1}">Next &#8594;</a>'
    pag += f'<span style="color:#666;font-size:0.8rem">({total} total)</span></div>'

    body = f'<div class="section"><h2>All Findings — Page {page}</h2>{table}{pag}</div>'
    return page_wrap(f"Findings — Page {page}", body)


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"Dashboard starting on http://0.0.0.0:5555")
    print(f"ROOT: {ROOT}")
    print(f"State file : {WATCHER_STATE}")
    print(f"Findings   : {MERGED_FINDINGS}")
    print(f"Alerts log : {ALERTS_LOG}")
    app.run(host="0.0.0.0", port=5555, debug=False)
