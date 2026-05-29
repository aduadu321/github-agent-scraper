#!/usr/bin/env python3
"""
_captcha_hunt.py — Targeted CAPTCHA-solver API key hunter.

Loads CAPTCHA dork queries from patterns.py, hits GitHub /search/code,
fetches raw file content, scans with capmonster/anticaptcha/2captcha/capsolver/
deathbycaptcha patterns, and writes findings to output/hunt_captcha.json.

Rate-limit: 6-second sleep between queries (30 max results per query).
Keys are NEVER printed in full — always masked.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent
OUTPUT_DIR = ROOT / "output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

ENV_FILE = Path(r"C:\Users\aduad\tools\llm-rotate\.env")
SLEEP_BETWEEN_QUERIES = 6  # seconds — respects GitHub rate limits
MAX_PER_QUERY = 30

# ---------------------------------------------------------------------------
# Token loader
# ---------------------------------------------------------------------------

def _load_token() -> str:
    tok = os.environ.get("GITHUB_TOKEN", "").strip()
    if tok:
        return tok
    if ENV_FILE.exists():
        for raw in ENV_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
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
    return ""


# ---------------------------------------------------------------------------
# CAPTCHA patterns (inline, mirrored from patterns.py additions)
# ---------------------------------------------------------------------------

CAPTCHA_PATTERNS: dict[str, dict] = {
    "capmonster_key": {
        "regex": re.compile(
            r"(?i)(?:capmonster|cap_monster)(?:[\s\-_]*(?:api|key|token|secret|client))?[\s]*[=:\"'`]+\s*([a-f0-9]{32})"
        ),
        "severity": "HIGH",
        "description": "CapMonster cloud API key (32-char hex)",
        "false_positive_hints": ["example", "test", "00000000", "ffffffff", "aaaaaa"],
    },
    "anticaptcha_key": {
        "regex": re.compile(
            r"(?i)(?:anti.?captcha|anticaptcha)(?:[\s\-_]*(?:api|key|token))?[\s]*[=:\"'`]+\s*([a-f0-9]{32})"
        ),
        "severity": "HIGH",
        "description": "Anti-Captcha API key (32-char hex)",
        "false_positive_hints": ["example", "test", "0000000000"],
    },
    "twocaptcha_key": {
        "regex": re.compile(
            r"(?i)(?:2captcha|two_?captcha|rucaptcha)(?:[\s\-_]*(?:api|key|token))?[\s]*[=:\"'`]+\s*([a-f0-9]{32})"
        ),
        "severity": "HIGH",
        "description": "2Captcha / RuCaptcha API key",
        "false_positive_hints": ["example", "test"],
    },
    "capsolver_key": {
        "regex": re.compile(
            r"(?i)(?:capsolver|cap_solver)(?:[\s\-_]*(?:api|key|token))?[\s]*[=:\"'`]+\s*(CAP-[a-zA-Z0-9]{32,})"
        ),
        "severity": "HIGH",
        "description": "CapSolver API key (CAP- prefix)",
        "false_positive_hints": ["example"],
    },
    "deathbycaptcha_key": {
        "regex": re.compile(
            r"(?i)(?:deathbycaptcha|dbc)(?:[\s\-_]*(?:api|key|pass|password|username))?[\s]*[=:\"'`]+\s*([a-zA-Z0-9]{8,40})"
        ),
        "severity": "MEDIUM",
        "description": "DeathByCaptcha credentials",
        "false_positive_hints": ["example", "test"],
    },
}

# CAPTCHA dork queries (category: hunt_captcha)
CAPTCHA_DORKS: list[str] = [
    "CAPMONSTER_API_KEY filename:.env",
    "capmonster.cloud apiKey filename:.env",
    "CAPMONSTER_KEY= filename:.env",
    "ANTI_CAPTCHA_KEY filename:.env",
    "TWOCAPTCHA_API_KEY filename:.env",
    "2captcha apikey filename:.env",
    "capmonster_cloud_key extension:py",
    "capsolver API_KEY CAP- filename:.env",
    "rucaptcha key filename:.env",
    "deathbycaptcha username password filename:.env",
]


# ---------------------------------------------------------------------------
# Masking helper — never print full key
# ---------------------------------------------------------------------------

def _mask(s: str) -> str:
    if len(s) <= 12:
        return s[:4] + "***"
    return s[:8] + "..." + s[-4:]


# ---------------------------------------------------------------------------
# False-positive check
# ---------------------------------------------------------------------------

def _is_fp(matched: str, hints: list[str]) -> bool:
    lower = matched.lower()
    return any(h.lower() in lower for h in hints if h)


# ---------------------------------------------------------------------------
# GitHub code search — returns list of result dicts
# ---------------------------------------------------------------------------

def _github_search(query: str, token: str, max_results: int = 30) -> list[dict]:
    """Call GitHub /search/code API and return items list."""
    per_page = min(max_results, 30)
    url = (
        "https://api.github.com/search/code"
        f"?q={urllib.request.quote(query)}"
        f"&per_page={per_page}"
        "&sort=indexed"
        "&order=desc"
    )
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "aduadu321-captcha-hunt/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("items", [])
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"    [WARN] HTTP {e.code} on search: {body[:200]}")
        if e.code == 422:
            return []
        if e.code in (403, 429):
            print("    [WARN] Rate limited — sleeping 60s")
            time.sleep(60)
        return []
    except Exception as exc:
        print(f"    [WARN] Search error: {exc}")
        return []


# ---------------------------------------------------------------------------
# Raw file fetcher
# ---------------------------------------------------------------------------

def _fetch_raw(owner: str, repo: str, branch: str, path: str, token: str) -> str | None:
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    headers = {
        "User-Agent": "aduadu321-captcha-hunt/1.0",
        "Accept": "text/plain, */*",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                return raw.decode("latin-1", errors="replace")
    except urllib.error.HTTPError as e:
        if e.code in (404, 403, 451):
            return None
        if e.code == 429:
            print(f"    [WARN] 429 fetching raw — sleeping 30s")
            time.sleep(30)
        return None
    except Exception as exc:
        print(f"    [WARN] Raw fetch error: {exc}")
        return None


def _branch_from_html_url(html_url: str) -> str:
    if "/blob/" in html_url:
        try:
            after = html_url.split("/blob/", 1)[1]
            return after.split("/", 1)[0]
        except IndexError:
            pass
    return "main"


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def _scan(content: str, filename: str = "") -> list[dict]:
    results: list[dict] = []
    lines = content.splitlines()
    for name, pat in CAPTCHA_PATTERNS.items():
        regex: re.Pattern = pat["regex"]
        for lineno, line in enumerate(lines, 1):
            for m in regex.finditer(line):
                # group(1) if captured, else group(0)
                matched = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                is_fp = _is_fp(matched, pat["false_positive_hints"])
                results.append({
                    "pattern_name": name,
                    "severity": pat["severity"],
                    "description": pat["description"],
                    "matched_masked": _mask(matched),
                    "matched_len": len(matched),
                    "line_no": lineno,
                    "is_fp_hint": is_fp,
                })
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    out_path = OUTPUT_DIR / "hunt_captcha.json"
    token = _load_token()
    if not token:
        print("[ERROR] No GITHUB_TOKEN found — results will be rate-limited/empty")

    all_findings: list[dict] = []
    dedup: set[str] = set()

    print(f"\n{'='*60}")
    print(f"  CAPTCHA solver key hunt — {len(CAPTCHA_DORKS)} dork queries")
    print(f"  Max {MAX_PER_QUERY} results/query | {SLEEP_BETWEEN_QUERIES}s sleep between queries")
    print(f"  Output: {out_path}")
    print(f"{'='*60}\n")

    for idx, dork in enumerate(CAPTCHA_DORKS, 1):
        print(f"[{idx:02d}/{len(CAPTCHA_DORKS)}] {dork}")
        items = _github_search(dork, token, max_results=MAX_PER_QUERY)
        print(f"        -> {len(items)} results")

        for item in items:
            full_name: str = item.get("repository", {}).get("full_name") or ""
            path: str = item.get("path") or ""
            html_url: str = item.get("html_url") or ""
            if not full_name or not path:
                continue
            parts = full_name.split("/", 1)
            if len(parts) != 2:
                continue
            owner, repo = parts
            branch = _branch_from_html_url(html_url)

            content = _fetch_raw(owner, repo, branch, path, token)
            time.sleep(0.5)

            if not content:
                continue

            hits = _scan(content, filename=Path(path).name)
            for hit in hits:
                dedup_key = f"{full_name}|{path}|{hit['pattern_name']}|{hit['line_no']}"
                if dedup_key in dedup:
                    continue
                dedup.add(dedup_key)

                finding = {
                    "repo": full_name,
                    "path": path,
                    "html_url": html_url,
                    "branch": branch,
                    "dork_query": dork,
                    **hit,
                    "scanned_at": datetime.now(timezone.utc).isoformat(),
                }
                all_findings.append(finding)

                fp_label = "[FP-HINT]" if hit["is_fp_hint"] else "[FINDING]"
                print(
                    f"        {fp_label} {hit['severity']:<8} "
                    f"{hit['pattern_name']:<22} "
                    f"{full_name}/{path}:{hit['line_no']} "
                    f"key={hit['matched_masked']}"
                )

        # 6-second sleep between dork queries to respect rate limits
        if idx < len(CAPTCHA_DORKS):
            time.sleep(SLEEP_BETWEEN_QUERIES)

    # Write output
    out_path.write_text(
        json.dumps(all_findings, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # Summary report
    real_findings = [f for f in all_findings if not f["is_fp_hint"]]
    fp_findings = [f for f in all_findings if f["is_fp_hint"]]

    print(f"\n{'='*60}")
    print(f"  Hunt complete")
    print(f"  Total hits     : {len(all_findings)}")
    print(f"  Real findings  : {len(real_findings)}")
    print(f"  FP-hint hits   : {len(fp_findings)}")
    print(f"  Output file    : {out_path}")
    print(f"{'='*60}\n")

    if real_findings:
        print("Real findings summary (masked):")
        print(f"  {'REPO':<35} {'PATH':<30} {'PATTERN':<22} {'SEV':<8} {'MASKED KEY'}")
        print(f"  {'-'*35} {'-'*30} {'-'*22} {'-'*8} {'-'*20}")
        for f in real_findings:
            print(
                f"  {f['repo'][:35]:<35} "
                f"{f['path'][:30]:<30} "
                f"{f['pattern_name']:<22} "
                f"{f['severity']:<8} "
                f"{f['matched_masked']}"
            )
    else:
        print("No real (non-FP-hint) CAPTCHA keys found in this run.")


if __name__ == "__main__":
    main()
