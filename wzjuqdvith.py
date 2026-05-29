#!/usr/bin/env python3
"""
GitHub secret / API-key hunter.

CLI:
    python hunt_secrets.py [--category openai|anthropic|github|aws|all]
                           [--max-per-query 30]
                           [--severity CRITICAL|HIGH|MEDIUM|all]
                           [--out output/myscan]
                           [--dry-run]
                           [--no-fetch]

Requires scraper.py in same directory.
Imports patterns.py if available; falls back to inline FALLBACK_PATTERNS.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Project root
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent
LOG_DIR = ROOT / "logs"
OUTPUT_DIR = ROOT / "output"
LOG_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("hunt_secrets")
if not logger.handlers:
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler(LOG_DIR / "hunt_secrets.log", encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s\t%(levelname)s\t%(message)s"))
    logger.addHandler(fh)
    sh = logging.StreamHandler()
    sh.setLevel(logging.WARNING)
    sh.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(sh)

# ---------------------------------------------------------------------------
# ANSI colors (stdout only; disable if not a tty)
# ---------------------------------------------------------------------------

USE_COLOR = sys.stdout.isatty()

_COLORS = {
    "CRITICAL": "\033[1;31m",   # bold red
    "HIGH":     "\033[1;33m",   # bold yellow
    "MEDIUM":   "\033[1;34m",   # bold blue
    "RESET":    "\033[0m",
    "DIM":      "\033[2m",
    "CYAN":     "\033[36m",
    "GREEN":    "\033[32m",
}


def _c(key: str, text: str) -> str:
    if not USE_COLOR:
        return text
    return f"{_COLORS.get(key, '')}{text}{_COLORS['RESET']}"


# ---------------------------------------------------------------------------
# Fallback patterns (used if patterns.py is not ready)
# ---------------------------------------------------------------------------

FALLBACK_PATTERNS: dict[str, dict] = {
    "openai": {
        "regex": r"sk-[a-zA-Z0-9]{20,60}",
        "severity": "CRITICAL",
        "false_positive_hints": ["sk-xxxx", "sk-your", "sk-test"],
    },
    "github_pat": {
        "regex": r"ghp_[a-zA-Z0-9]{36}",
        "severity": "HIGH",
        "false_positive_hints": [],
    },
    "aws_key": {
        "regex": r"AKIA[0-9A-Z]{16}",
        "severity": "CRITICAL",
        "false_positive_hints": [],
    },
    "huggingface": {
        "regex": r"hf_[a-zA-Z0-9]{34}",
        "severity": "HIGH",
        "false_positive_hints": ["hf_xxxx"],
    },
    "anthropic": {
        "regex": r"sk-ant-[a-zA-Z0-9\-_]{20,80}",
        "severity": "CRITICAL",
        "false_positive_hints": ["sk-ant-xxxx", "sk-ant-your", "sk-ant-test"],
    },
    "generic_secret": {
        "regex": r'(?i)(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token)\s*[=:]\s*["\']?([a-zA-Z0-9\-_]{20,80})["\']?',
        "severity": "MEDIUM",
        "false_positive_hints": ["your_api_key", "your_secret", "placeholder", "xxxx", "changeme"],
    },
}

FALLBACK_DORKS: list[dict] = [
    {"q": "OPENAI_API_KEY= filename:.env", "kind": "code", "qualifiers": {}, "category": "openai"},
    {"q": "ANTHROPIC_API_KEY= filename:.env", "kind": "code", "qualifiers": {}, "category": "anthropic"},
    {"q": "GITHUB_TOKEN= filename:.env", "kind": "code", "qualifiers": {}, "category": "github"},
    {"q": "AWS_ACCESS_KEY_ID AKIA filename:.env", "kind": "code", "qualifiers": {}, "category": "aws"},
    {"q": "hf_ filename:config.json", "kind": "code", "qualifiers": {}, "category": "huggingface"},
]

# ---------------------------------------------------------------------------
# Import patterns.py (with fallback)
# ---------------------------------------------------------------------------

try:
    from patterns import PATTERNS, GITHUB_DORK_QUERIES, scan_text  # type: ignore
    _patterns_ok = True
    logger.info("Loaded patterns.py successfully")
except ImportError:
    _patterns_ok = False
    logger.warning("patterns.py not found — using fallback inline patterns")
    PATTERNS = FALLBACK_PATTERNS  # type: ignore

    GITHUB_DORK_QUERIES: list[dict] = FALLBACK_DORKS  # type: ignore

    def scan_text(content: str, filename: str = "") -> list[dict]:  # type: ignore
        """Minimal inline scanner using FALLBACK_PATTERNS."""
        hits: list[dict] = []
        lines = content.splitlines()
        for name, pat in FALLBACK_PATTERNS.items():
            compiled = re.compile(pat["regex"])
            for lineno, line in enumerate(lines, 1):
                for m in compiled.finditer(line):
                    matched = m.group(0)
                    fp_hints = pat.get("false_positive_hints", [])
                    is_fp = any(h.lower() in matched.lower() for h in fp_hints if h)
                    hits.append({
                        "pattern_name": name,
                        "severity": pat["severity"],
                        "matched_text": matched,
                        "line_no": lineno,
                        "is_fp_hint": is_fp,
                    })
        return hits


# ---------------------------------------------------------------------------
# Token loading (same logic as scraper.py)
# ---------------------------------------------------------------------------

ENV_FALLBACK = Path(r"C:\Users\aduad\tools\llm-rotate\.env")


def _load_token() -> str:
    tok = os.environ.get("GITHUB_TOKEN", "").strip()
    if tok:
        return tok
    if ENV_FALLBACK.exists():
        try:
            for raw in ENV_FALLBACK.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[len("export "):]
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                if k.strip() == "GITHUB_TOKEN":
                    v = v.strip().strip('"').strip("'")
                    if v:
                        return v
        except OSError:
            pass
    return ""


# ---------------------------------------------------------------------------
# Raw file fetcher
# ---------------------------------------------------------------------------

USER_AGENT = "aduadu321-hunt-secrets/1.0"


def _raw_url(owner: str, repo: str, branch: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"


def _fetch_raw(url: str, token: str, retries: int = 3) -> str | None:
    """Fetch raw file content; returns None on failure."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/plain, */*",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=20) as resp:
                raw = resp.read()
                # Try UTF-8 first, then latin-1 as fallback
                try:
                    return raw.decode("utf-8")
                except UnicodeDecodeError:
                    return raw.decode("latin-1", errors="replace")
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = 30 * attempt
                logger.warning("429 on raw fetch %s — sleeping %ds", url, wait)
                time.sleep(wait)
                continue
            if e.code in (404, 403, 451):
                logger.debug("HTTP %d on %s — skip", e.code, url)
                return None
            if 500 <= e.code < 600 and attempt < retries:
                time.sleep(2 ** attempt)
                continue
            logger.warning("HTTP %d fetching %s", e.code, url)
            return None
        except Exception as e:
            logger.warning("Fetch error %s: %s", url, e)
            if attempt < retries:
                time.sleep(2 ** attempt)
    return None


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

_SEV_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "INFO": 0}


def _sev_ge(sev: str, threshold: str) -> bool:
    """Return True if sev >= threshold in severity order."""
    if threshold.lower() == "all":
        return True
    return _SEV_ORDER.get(sev.upper(), 0) >= _SEV_ORDER.get(threshold.upper(), 0)


# ---------------------------------------------------------------------------
# Build raw_url from code-search result
# ---------------------------------------------------------------------------

def _build_raw_url(row: dict) -> tuple[str, str, str, str] | None:
    """
    Given a code-search row from scraper.search(), derive:
      (owner, repo, branch, path)
    Returns None if required fields are missing.
    """
    full_name: str = row.get("repo_full_name") or ""
    path: str = row.get("path") or ""
    if not full_name or not path:
        return None
    # html_url format: https://github.com/{owner}/{repo}/blob/{branch}/{path}
    html_url: str = row.get("html_url") or ""
    branch = "main"  # default guess
    if "/blob/" in html_url:
        try:
            after_blob = html_url.split("/blob/", 1)[1]
            branch = after_blob.split("/", 1)[0]
        except IndexError:
            pass
    parts = full_name.split("/", 1)
    if len(parts) != 2:
        return None
    owner, repo = parts
    return owner, repo, branch, path


# ---------------------------------------------------------------------------
# Main hunt logic
# ---------------------------------------------------------------------------

def _truncate(s: str, n: int = 60) -> str:
    return s if len(s) <= n else s[:n] + "..."


def run_hunt(
    category: str = "all",
    max_per_query: int = 30,
    severity_threshold: str = "HIGH",
    out_prefix: str | None = None,
    dry_run: bool = False,
    no_fetch: bool = False,
) -> list[dict]:
    """
    Core hunt routine. Returns list of finding dicts.
    """
    from scraper import search  # noqa: PLC0415 — lazy import to keep startup fast

    token = _load_token()

    # ---- Filter dork queries by category -----------------------------------
    if category.lower() == "all":
        dorks = GITHUB_DORK_QUERIES
    elif "," in category:
        cats = {c.strip().lower() for c in category.split(",")}
        dorks = [d for d in GITHUB_DORK_QUERIES if d.get("category", "").lower() in cats]
    else:
        dorks = [d for d in GITHUB_DORK_QUERIES if d.get("category", "").lower() == category.lower()]

    if not dorks:
        print(f"No dork queries matched category={category!r}")
        return []

    # ---- Dry-run -----------------------------------------------------------
    if dry_run:
        print(f"\n{'='*60}")
        print(f"Dry-run: {len(dorks)} dork queries for category={category!r}")
        print(f"{'='*60}")
        for i, d in enumerate(dorks, 1):
            print(f"  [{i:02d}] category={d.get('category','?'):<15} kind={d.get('kind','code'):<6}  q={d['q']}")
        print(f"\nMax results per query: {max_per_query}")
        print(f"Severity threshold   : {severity_threshold}")
        print(f"Fetch full files     : {not no_fetch}")
        return []

    # ---- Dedup key: (repo+path+pattern_name) → best finding ---------------
    dedup: dict[str, dict] = {}

    total_queries = 0
    total_code_results = 0
    total_raw_fetches = 0
    total_scan_hits = 0

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    print(f"\n{_c('CYAN', 'Hunt starting')} — {len(dorks)} queries, max {max_per_query}/query, severity>={severity_threshold}")
    print()

    for dork_idx, dork in enumerate(dorks, 1):
        q: str = dork["q"]
        kind: str = dork.get("kind", "code")
        qualifiers: dict = dork.get("qualifiers", {})
        cat: str = dork.get("category", "")

        print(f"  [{dork_idx}/{len(dorks)}] {_c('CYAN', cat):<20} {q}")

        try:
            rows = search(
                q,
                kind=kind,
                max_results=max_per_query,
                **qualifiers,
            )
        except Exception as e:
            logger.warning("Search error for dork %r: %s", q, e)
            print(f"    {_c('HIGH', 'WARN')} search error: {e}")
            continue

        total_queries += 1
        total_code_results += len(rows)
        logger.info("dork=%r results=%d", q, len(rows))

        for row in rows:
            repo: str = row.get("repo_full_name") or ""
            path: str = row.get("path") or ""
            html_url: str = row.get("html_url") or ""
            repo_stars: Any = row.get("repo_stars")
            repo_pushed_at: str = row.get("repo_pushed_at") or ""
            scanned_at: str = datetime.now(timezone.utc).isoformat()

            content_to_scan: str = ""
            raw_url: str = ""
            actual_branch: str = "main"

            coords = _build_raw_url(row)
            if coords:
                owner, repo_name, branch, fpath = coords
                actual_branch = branch
                raw_url = _raw_url(owner, repo_name, branch, fpath)
            else:
                logger.debug("Could not build raw URL for row: %s", row)

            if no_fetch or not raw_url:
                # Use snippet from search result if available, otherwise empty
                content_to_scan = row.get("snippet") or row.get("text_matches") or q
            else:
                total_raw_fetches += 1
                content_to_scan = _fetch_raw(raw_url, token) or ""
                time.sleep(0.3)  # polite delay

            if not content_to_scan:
                continue

            try:
                hits = scan_text(content_to_scan, filename=Path(path).name if path else "")
            except Exception as e:
                logger.warning("scan_text error on %s/%s: %s", repo, path, e)
                hits = []

            for hit in hits:
                sev: str = hit.get("severity", "MEDIUM")
                if not _sev_ge(sev, severity_threshold):
                    continue

                pattern_name: str = hit.get("pattern_name", "")
                matched_text: str = hit.get("matched_text", "")
                line_no: int = hit.get("line_no", 0)
                is_fp: bool = bool(hit.get("is_fp_hint", False))

                total_scan_hits += 1

                finding: dict = {
                    "query": q,
                    "repo": repo,
                    "path": path,
                    "html_url": html_url,
                    "raw_url": raw_url,
                    "pattern_name": pattern_name,
                    "severity": sev,
                    "matched_text": matched_text,
                    "line_no": line_no,
                    "is_fp_hint": is_fp,
                    "repo_stars": repo_stars,
                    "repo_pushed_at": repo_pushed_at,
                    "scanned_at": scanned_at,
                }

                dedup_key = f"{repo}|{path}|{pattern_name}"
                existing = dedup.get(dedup_key)
                if existing is None:
                    dedup[dedup_key] = finding
                else:
                    # Prefer non-FP hit
                    if existing.get("is_fp_hint") and not is_fp:
                        dedup[dedup_key] = finding

                # Live stdout line
                fp_tag = _c("DIM", "FP:yes") if is_fp else _c("GREEN", "FP:no")
                sev_tag = _c(sev, f"[{sev}]")
                print(
                    f"    {sev_tag} {_c('CYAN', repo)}  {path}  "
                    f"line:{line_no}  {pattern_name}  "
                    f"{_truncate(matched_text, 30)}  ({fp_tag})"
                )

    findings = list(dedup.values())

    # ---- Stats -------------------------------------------------------------
    print()
    print(f"{_c('CYAN', 'Summary')}")
    print(f"  Dork queries run    : {total_queries}")
    print(f"  Code results fetched: {total_code_results}")
    print(f"  Raw file fetches    : {total_raw_fetches}")
    print(f"  Pattern scan hits   : {total_scan_hits}")
    print(f"  Unique findings     : {len(findings)}  (after dedup, sev>={severity_threshold})")

    # ---- Write output files ------------------------------------------------
    if out_prefix:
        base = Path(out_prefix)
        if not base.is_absolute():
            base = ROOT / base
    else:
        base = OUTPUT_DIR / f"secrets_{ts}"

    json_path = base.parent / (base.name + ".json")
    csv_path = base.parent / (base.name + ".csv")
    json_path.parent.mkdir(parents=True, exist_ok=True)

    with json_path.open("w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)

    csv_cols = [
        "query", "repo", "path", "html_url", "raw_url",
        "pattern_name", "severity", "matched_text", "line_no",
        "is_fp_hint", "repo_stars", "repo_pushed_at", "scanned_at",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=csv_cols, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(findings)

    print()
    print(f"  JSON -> {json_path}")
    print(f"  CSV  -> {csv_path}")

    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="GitHub secret/API-key hunter")
    p.add_argument(
        "--category",
        default="all",
        help="Filter dork queries by category (openai|anthropic|github|aws|huggingface|all). Default: all",
    )
    p.add_argument(
        "--max-per-query",
        dest="max_per_query",
        type=int,
        default=30,
        help="Max code-search results per dork query (GitHub cap=100). Default: 30",
    )
    p.add_argument(
        "--severity",
        default="HIGH",
        help="Minimum severity to report: CRITICAL|HIGH|MEDIUM|all. Default: HIGH",
    )
    p.add_argument(
        "--out",
        default=None,
        help="Output file prefix (without .json/.csv). Default: output/secrets_<timestamp>",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print dork plan and exit 0 without running queries",
    )
    p.add_argument(
        "--no-fetch",
        action="store_true",
        dest="no_fetch",
        help="Do not fetch full raw file — scan only the search result snippet (faster, less accurate)",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    if not _patterns_ok:
        print(f"{_c('HIGH', '[WARN]')} patterns.py not found — using inline fallback patterns ({len(FALLBACK_PATTERNS)} patterns, {len(FALLBACK_DORKS)} dorks)")

    run_hunt(
        category=args.category,
        max_per_query=args.max_per_query,
        severity_threshold=args.severity,
        out_prefix=args.out,
        dry_run=args.dry_run,
        no_fetch=args.no_fetch,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
