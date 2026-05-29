#!/usr/bin/env python3
"""
report.py — findings reporter for hunt_secrets.py output.

Usage:
    python report.py [--input GLOB] [--format html|csv|md|all]
                     [--out PREFIX] [--exclude-fp] [--min-severity HIGH]

Defaults:
    --input     output/secrets_*.json  (all files matching that glob)
    --format    all
    --out       output/report
"""

import argparse
import csv
import html as html_mod
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


# ── severity ordering (higher index = higher severity) ────────────────────────
SEV_ORDER = {"MEDIUM": 0, "HIGH": 1, "CRITICAL": 2}
SEV_COLORS = {"CRITICAL": "#c0392b", "HIGH": "#e67e22", "MEDIUM": "#f1c40f"}
SEV_BADGE_FG = {"CRITICAL": "#fff", "HIGH": "#fff", "MEDIUM": "#333"}


def severity_key(finding):
    return SEV_ORDER.get(finding.get("severity", "MEDIUM"), 0)


def mask(text: str) -> str:
    """Show first 6 + '...' + last 4 chars. Short strings fully masked."""
    if not text:
        return ""
    t = str(text)
    if len(t) <= 12:
        return t[:3] + "..." + t[-2:] if len(t) > 5 else "***"
    return t[:6] + "..." + t[-4:]


# ── I/O helpers ───────────────────────────────────────────────────────────────

def load_findings(paths: list[Path]) -> list[dict]:
    findings = []
    for p in paths:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, list):
                findings.extend(data)
        except Exception as e:
            print(f"[warn] could not load {p}: {e}", file=sys.stderr)
    return findings


def filter_findings(findings: list[dict], exclude_fp: bool, min_severity: str | None):
    result = findings
    if exclude_fp:
        result = [f for f in result if not f.get("is_fp_hint", False)]
    if min_severity and min_severity in SEV_ORDER:
        cutoff = SEV_ORDER[min_severity]
        result = [f for f in result if SEV_ORDER.get(f.get("severity", "MEDIUM"), 0) >= cutoff]
    return result


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (-severity_key(f), f.get("repo", ""), f.get("path", "")))


# ── CSV output ────────────────────────────────────────────────────────────────
COLUMNS = [
    "severity", "pattern_name", "repo", "path", "line_no",
    "query", "html_url", "raw_url", "matched_text",
    "is_fp_hint", "repo_stars", "repo_pushed_at", "scanned_at",
]


def write_csv(findings: list[dict], out_path: Path):
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        for f in findings:
            w.writerow({c: f.get(c, "") for c in COLUMNS})
    print(f"[csv]  wrote {out_path}")


# ── Markdown output ───────────────────────────────────────────────────────────

def write_md(findings: list[dict], out_path: Path, scan_date: str):
    lines = [f"# Secret Hunt Report — {scan_date}", ""]

    # Summary table
    sev_counts = Counter(f.get("severity", "MEDIUM") for f in findings)
    lines += ["## Summary", "| Severity | Count |", "|---|---|"]
    for sev in ("CRITICAL", "HIGH", "MEDIUM"):
        if sev in sev_counts:
            lines.append(f"| {sev} | {sev_counts[sev]} |")
    lines.append("")

    if not findings:
        lines.append("_No findings._")
        out_path.write_text("\n".join(lines), encoding="utf-8")
        print(f"[md]   wrote {out_path}")
        return

    lines.append("## Findings")
    lines.append("")

    grouped = defaultdict(list)
    for f in findings:
        grouped[f.get("severity", "MEDIUM")].append(f)

    for sev in ("CRITICAL", "HIGH", "MEDIUM"):
        if sev not in grouped:
            continue
        lines += [f"### {sev}", ""]
        for f in grouped[sev]:
            repo = f.get("repo", "?")
            stars = f.get("repo_stars", "?")
            path = f.get("path", "?")
            line_no = f.get("line_no", "?")
            query = f.get("query", "?")
            html_url = f.get("html_url", "")
            matched = mask(f.get("matched_text", ""))
            fp = "Yes" if f.get("is_fp_hint") else "No"
            pattern = f.get("pattern_name", "?")

            lines += [
                f"#### {repo} — {matched}",
                f"- **Pattern**: `{pattern}`",
                f"- **Repo**: {repo} (⭐ {stars})",
                f"- **File**: `{path}` line {line_no}",
                f"- **Query**: `{query}`",
                f"- **Link**: {html_url}",
                f"- **FP hint**: {fp}",
                "",
            ]

    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[md]   wrote {out_path}")


# ── HTML output ───────────────────────────────────────────────────────────────

def _badge(sev: str) -> str:
    bg = SEV_COLORS.get(sev, "#aaa")
    fg = SEV_BADGE_FG.get(sev, "#333")
    return (f'<span class="badge" style="background:{bg};color:{fg};">'
            f'{html_mod.escape(sev)}</span>')


def write_html(findings: list[dict], out_path: Path, scan_date: str):
    total = len(findings)
    sev_counts = Counter(f.get("severity", "MEDIUM") for f in findings)
    fp_count = sum(1 for f in findings if f.get("is_fp_hint"))
    queries_seen = len(set(f.get("query", "") for f in findings))

    badges_html = " ".join(
        f'<span class="badge" style="background:{SEV_COLORS[s]};color:{SEV_BADGE_FG[s]};">'
        f'{s}: {sev_counts.get(s, 0)}</span>'
        for s in ("CRITICAL", "HIGH", "MEDIUM") if sev_counts.get(s, 0) > 0
    )

    CSS = """
    body{font-family:system-ui,sans-serif;margin:0;padding:0;background:#f5f6fa;}
    header{background:#1a1a2e;color:#eee;padding:1.2rem 2rem;}
    header h1{margin:0;font-size:1.5rem;}
    .meta{font-size:.85rem;color:#aaa;margin-top:.3rem;}
    .badge{display:inline-block;border-radius:4px;padding:2px 8px;
           font-size:.75rem;font-weight:700;letter-spacing:.5px;margin:0 2px;}
    main{padding:1.5rem 2rem;}
    details{margin-bottom:1rem;border:1px solid #ddd;border-radius:6px;background:#fff;}
    summary{padding:.7rem 1rem;cursor:pointer;font-weight:700;list-style:none;
            display:flex;align-items:center;gap:.5rem;}
    summary::-webkit-details-marker{display:none;}
    table{width:100%;border-collapse:collapse;font-size:.82rem;}
    th{background:#2d3561;color:#fff;padding:6px 10px;text-align:left;}
    td{padding:5px 10px;border-bottom:1px solid #eee;vertical-align:top;word-break:break-all;}
    tr:hover td{background:#f0f4ff;}
    a{color:#2d3561;text-decoration:none;}
    a:hover{text-decoration:underline;}
    .fp-yes{color:#e74c3c;font-weight:bold;}
    footer{text-align:center;padding:1rem;color:#888;font-size:.78rem;
           border-top:1px solid #ddd;margin-top:2rem;}
    """

    grouped = defaultdict(list)
    for f in findings:
        grouped[f.get("severity", "MEDIUM")].append(f)

    sections_html = ""
    for sev in ("CRITICAL", "HIGH", "MEDIUM"):
        group = grouped.get(sev, [])
        if not group:
            continue
        bg = SEV_COLORS[sev]
        fg = SEV_BADGE_FG[sev]
        rows_html = ""
        for f in group:
            repo = html_mod.escape(f.get("repo", ""))
            path_esc = html_mod.escape(f.get("path", ""))
            html_url = html_mod.escape(f.get("html_url", ""))
            pattern = html_mod.escape(f.get("pattern_name", ""))
            matched = html_mod.escape(mask(f.get("matched_text", "")))
            stars = f.get("repo_stars", "?")
            fp = f.get("is_fp_hint", False)
            fp_cell = ('<span class="fp-yes">⚠ Yes</span>' if fp else "No")
            repo_url = f"https://github.com/{html_mod.escape(f.get('repo', ''))}"
            rows_html += (
                f"<tr>"
                f"<td>{_badge(sev)}</td>"
                f"<td>{pattern}</td>"
                f'<td><a href="{repo_url}" target="_blank">{repo}</a> ⭐{stars}</td>'
                f'<td><a href="{html_url}" target="_blank">{path_esc}</a></td>'
                f"<td><code>{matched}</code></td>"
                f"<td>{fp_cell}</td>"
                f"</tr>\n"
            )
        sections_html += f"""
<details open>
  <summary>
    <span class="badge" style="background:{bg};color:{fg};">{sev}</span>
    {len(group)} finding{"s" if len(group)!=1 else ""}
  </summary>
  <table>
    <thead><tr>
      <th>Severity</th><th>Pattern</th><th>Repo</th>
      <th>File (link)</th><th>Matched (masked)</th><th>FP hint</th>
    </tr></thead>
    <tbody>
{rows_html}    </tbody>
  </table>
</details>
"""

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secret Hunt Report — {html_mod.escape(scan_date)}</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <h1>Secret Hunt Report</h1>
  <div class="meta">
    Scan date: {html_mod.escape(scan_date)} &nbsp;|&nbsp;
    Queries: {queries_seen} &nbsp;|&nbsp;
    Total findings: {total} &nbsp;|&nbsp;
    FP hints: {fp_count}
    &nbsp; {badges_html}
  </div>
</header>
<main>
{sections_html if sections_html else "<p><em>No findings.</em></p>"}
</main>
<footer>Generated by github-scraper hunt_secrets.py</footer>
</body>
</html>
"""
    out_path.write_text(doc, encoding="utf-8")
    print(f"[html] wrote {out_path}")


# ── Console summary ───────────────────────────────────────────────────────────

def print_summary(findings: list[dict], all_findings: list[dict], scan_date: str):
    total = len(findings)
    fp_count = sum(1 for f in all_findings if f.get("is_fp_hint"))
    queries = len(set(f.get("query", "") for f in all_findings))
    files_scanned = len(set((f.get("repo", ""), f.get("path", "")) for f in all_findings))
    sev = Counter(f.get("severity", "MEDIUM") for f in findings)
    sev_str = ", ".join(
        f"{s}:{sev[s]}" for s in ("CRITICAL", "HIGH", "MEDIUM") if sev.get(s)
    )

    print(
        f"Scan: {scan_date}  |  Queries: {queries}  |  "
        f"Files scanned: {files_scanned}  |  "
        f"Findings: {total} ({sev_str})  |  FP hints: {fp_count}"
    )

    # top repos
    repo_counts = Counter(f.get("repo", "?") for f in findings)
    repo_stars = {f.get("repo", "?"): f.get("repo_stars", "?") for f in findings}
    top = repo_counts.most_common(5)
    if top:
        print("Top repos by finding count:")
        for repo, cnt in top:
            stars = repo_stars.get(repo, "?")
            print(f"  {repo}  ({cnt} finding{'s' if cnt!=1 else ''}, ⭐ {stars})")


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="Secret hunt findings reporter")
    p.add_argument(
        "--input", default="output/secrets_*.json",
        help="Glob pattern for input JSON files (default: output/secrets_*.json)"
    )
    p.add_argument(
        "--format", default="all", choices=["html", "csv", "md", "all"],
        help="Output format(s)"
    )
    p.add_argument(
        "--out", default="output/report",
        help="Output path prefix (extensions added automatically)"
    )
    p.add_argument(
        "--exclude-fp", action="store_true",
        help="Skip findings where is_fp_hint=true"
    )
    p.add_argument(
        "--min-severity", choices=["MEDIUM", "HIGH", "CRITICAL"], default=None,
        help="Minimum severity to include"
    )
    return p.parse_args()


def main():
    # Ensure stdout handles Unicode on Windows (CP1252 consoles drop emoji)
    if sys.stdout.encoding and sys.stdout.encoding.lower().startswith("cp"):
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

    args = parse_args()

    # Resolve input files — support direct path or glob
    input_path = Path(args.input)
    if input_path.exists() and input_path.is_file():
        input_files = [input_path]
    else:
        # glob relative to cwd
        base = input_path.parent
        pattern = input_path.name
        if not base.is_absolute():
            base = Path.cwd() / base
        input_files = sorted(base.glob(pattern))

    if not input_files:
        print(f"[warn] no files matched: {args.input}", file=sys.stderr)

    all_findings = load_findings(input_files)
    findings = filter_findings(all_findings, args.exclude_fp, args.min_severity)
    findings = sort_findings(findings)

    scan_date = datetime.now().strftime("%Y-%m-%d")
    out_prefix = Path(args.out)
    out_prefix.parent.mkdir(parents=True, exist_ok=True)

    fmt = args.format
    if fmt in ("csv", "all"):
        write_csv(findings, out_prefix.with_suffix(".csv"))
    if fmt in ("md", "all"):
        write_md(findings, out_prefix.with_suffix(".md"), scan_date)
    if fmt in ("html", "all"):
        write_html(findings, out_prefix.with_suffix(".html"), scan_date)

    print_summary(findings, all_findings, scan_date)


if __name__ == "__main__":
    main()
