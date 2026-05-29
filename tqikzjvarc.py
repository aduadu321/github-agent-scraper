#!/usr/bin/env python3
"""
gist_hunter.py — Scans public GitHub Gists for secrets/API keys.

CLI:
    python gist_hunter.py [--query "api_key"] [--stream --max 500] [--out output/gists.json]
    python gist_hunter.py --max 20 --out output/gist_test.json
    python gist_hunter.py --max 200 --out output/gists.json --severity HIGH

Importable:
    from gist_hunter import stream_public_gists, scan_gist, search_gists_for_secrets

Stdlib only. Reads GITHUB_TOKEN from env or C:\\Users\\aduad\\tools\\llm-rotate\\.env (fallback).
"""

from __future__ import annotations

import argparse
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
from typing import Any, Iterator

# ──────────────────────────────────────────────────────────────────────────────
# Paths / constants
# ──────────────────────────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parent
LOG_DIR = ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "gist_hunter.log"

GITHUB_API = "https://api.github.com"
API_VERSION = "2022-11-28"
USER_AGENT = "aduadu321-github-scraper/1.0"
ENV_FALLBACK = Path(r"C:\Users\aduad\tools\llm-rotate\.env")

# Public gists: API caps pagination at 3000 gists (30 pages × 100 per page)
GIST_HARD_CAP = 3000

# Extensions to scan (low value = high-risk filetype)
HIGH_VALUE_EXTS = {
    ".env", ".sh", ".py", ".js", ".ts", ".json", ".yaml", ".yml",
    ".conf", ".ini", ".rb", ".php", ".toml", ".cfg", ".properties",
    ".tf", ".tfvars", ".gradle", ".xml", ".pem", ".key",
}
# Filenames that are almost always high-value
HIGH_VALUE_NAMES = {
    ".env", ".envrc", ".env.local", ".env.production", ".env.development",
    "credentials", "secrets", "config", "settings", "key", "token",
}

# Gist-specific scan patterns (supplement patterns.py)
GIST_INLINE_PATTERNS: dict[str, dict] = {
    "openai_key": {
        "regex": r"sk-[a-zA-Z0-9]{20,60}",
        "severity": "CRITICAL",
        "fp_hints": ["sk-xxxx", "sk-your", "sk-test", "sk-example", "sk-placeholder"],
    },
    "openai_project_key": {
        "regex": r"sk-proj-[a-zA-Z0-9_\-]{40,120}",
        "severity": "CRITICAL",
        "fp_hints": ["sk-proj-xxxx", "sk-proj-your", "sk-proj-test"],
    },
    "anthropic_key": {
        "regex": r"sk-ant-(?:api03-)?[a-zA-Z0-9_\-]{90,120}",
        "severity": "CRITICAL",
        "fp_hints": ["sk-ant-xxxx", "sk-ant-your", "sk-ant-test"],
    },
    "github_pat_classic": {
        "regex": r"ghp_[a-zA-Z0-9]{36}",
        "severity": "CRITICAL",
        "fp_hints": ["ghp_xxxx", "ghp_your", "ghp_test"],
    },
    "github_pat_fine": {
        "regex": r"github_pat_[a-zA-Z0-9_]{82}",
        "severity": "CRITICAL",
        "fp_hints": ["github_pat_xxxx"],
    },
    "aws_access_key": {
        "regex": r"AKIA[0-9A-Z]{16}",
        "severity": "CRITICAL",
        "fp_hints": ["AKIAIOSFODNN7EXAMPLE", "AKIAXXXXXXXXXXXXXXXX"],
    },
    "google_api_key": {
        "regex": r"AIza[0-9A-Za-z\-_]{30,40}",
        "severity": "HIGH",
        "fp_hints": ["AIzaxxxx", "AIzaYOUR", "AIzaSyEXAMPLE"],
    },
    "groq_key": {
        "regex": r"gsk_[a-zA-Z0-9]{50,70}",
        "severity": "CRITICAL",
        "fp_hints": ["gsk_xxxx", "gsk_your", "gsk_test"],
    },
    "huggingface_token": {
        "regex": r"hf_[a-zA-Z0-9]{34,50}",
        "severity": "HIGH",
        "fp_hints": ["hf_xxxx", "hf_your", "hf_test"],
    },
    "stripe_secret_key": {
        "regex": r"sk_live_[0-9a-zA-Z]{24,48}",
        "severity": "CRITICAL",
        "fp_hints": ["sk_live_xxxx", "sk_live_your"],
    },
    "slack_bot_token": {
        "regex": r"xoxb-[0-9A-Za-z\-]{10,72}",
        "severity": "CRITICAL",
        "fp_hints": ["xoxb-xxxx", "xoxb-your"],
    },
    "discord_bot_token": {
        "regex": r"[MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9_\-]{6}\.[a-zA-Z0-9_\-]{27}",
        "severity": "CRITICAL",
        "fp_hints": ["xxxx", "your_token"],
    },
    "ssh_private_key": {
        "regex": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": "CRITICAL",
        "fp_hints": ["example", "test", "dummy", "placeholder"],
    },
    "env_assignment": {
        "regex": r"^[A-Z][A-Z0-9_]{3,40}\s*=\s*['\"]?([a-zA-Z0-9/+_\-\.]{30,})['\"]?\s*$",
        "severity": "MEDIUM",
        "fp_hints": ["example", "your_", "xxxx", "placeholder", "changeme", "default",
                     "localhost", "http", "true", "false", "none", "null"],
    },
}

_COMPILED = {
    name: re.compile(pat["regex"], re.MULTILINE)
    for name, pat in GIST_INLINE_PATTERNS.items()
}

# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────

logger = logging.getLogger("gist_hunter")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s\t%(levelname)s\t%(message)s"))
    logger.addHandler(fh)
    sh = logging.StreamHandler()
    sh.setLevel(logging.WARNING)
    sh.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(sh)

# ──────────────────────────────────────────────────────────────────────────────
# Token loading
# ──────────────────────────────────────────────────────────────────────────────

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

# ──────────────────────────────────────────────────────────────────────────────
# HTTP layer
# ──────────────────────────────────────────────────────────────────────────────

_LINK_RE = re.compile(r'<([^>]+)>;\s*rel="([^"]+)"')


def _parse_link_header(link: str | None) -> dict[str, str]:
    if not link:
        return {}
    return {rel: url for url, rel in _LINK_RE.findall(link)}


def _get_json(url: str, token: str, extra_headers: dict[str, str] | None = None,
              max_attempts: int = 5) -> tuple[Any, dict[str, str]]:
    """GET url → (parsed_json, response_headers). Handles 403/429 backoff."""
    headers: dict[str, str] = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": USER_AGENT,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update(extra_headers)

    req = urllib.request.Request(url, headers=headers, method="GET")
    attempt = 0
    while True:
        attempt += 1
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                hdrs = {k: v for k, v in resp.headers.items()}
                body = json.loads(raw.decode("utf-8")) if raw else {}
                # Sleep if rate limit low
                try:
                    remaining = int(hdrs.get("X-RateLimit-Remaining", "999"))
                    reset = int(hdrs.get("X-RateLimit-Reset", "0"))
                    if remaining < 2 and reset > 0:
                        wait = max(1, reset - int(time.time()) + 2)
                        logger.warning("Rate limit low (remaining=%d); sleeping %ds", remaining, wait)
                        time.sleep(wait)
                except ValueError:
                    pass
                return body, hdrs
        except urllib.error.HTTPError as e:
            hdrs = {k: v for k, v in (e.headers or {}).items()}
            body_text = ""
            try:
                body_text = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass

            if e.code in (403, 429):
                retry_after = hdrs.get("Retry-After")
                wait = 0
                if retry_after and retry_after.isdigit():
                    wait = int(retry_after) + 1
                else:
                    try:
                        reset = int(hdrs.get("X-RateLimit-Reset", "0"))
                        if reset > 0:
                            wait = max(1, reset - int(time.time()) + 2)
                    except ValueError:
                        wait = 60
                wait = max(wait, 60)
                if attempt >= max_attempts:
                    raise RuntimeError(f"HTTP {e.code} after {attempt} attempts: {body_text[:200]}")
                logger.warning("HTTP %d; backing off %ds (attempt %d/%d)", e.code, wait, attempt, max_attempts)
                time.sleep(wait)
                continue

            if 500 <= e.code < 600 and attempt < max_attempts:
                wait = min(2 ** attempt, 30)
                logger.warning("HTTP %d server error; retrying in %ds", e.code, wait)
                time.sleep(wait)
                continue

            raise RuntimeError(f"HTTP {e.code}: {body_text[:200]}")
        except urllib.error.URLError as e:
            if attempt >= max_attempts:
                raise RuntimeError(f"Network error: {e}")
            time.sleep(min(2 ** attempt, 30))


def _fetch_raw(url: str, timeout: int = 15) -> str:
    """Fetch raw file content (no token — public gist raw URLs don't require auth)."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        logger.debug("raw fetch failed for %s: %s", url, e)
        return ""

# ──────────────────────────────────────────────────────────────────────────────
# Pattern scanning
# ──────────────────────────────────────────────────────────────────────────────

def _load_scan_fn():
    """Try to load scan_text from patterns.py; fall back to inline scanner."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "patterns", ROOT / "patterns.py"
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.scan_text
    except Exception:
        return _scan_text_inline


def _scan_text_inline(text: str, filename: str = "") -> list[dict]:
    """Fallback inline scanner using GIST_INLINE_PATTERNS."""
    results: list[dict] = []
    for name, compiled in _COMPILED.items():
        pat = GIST_INLINE_PATTERNS[name]
        for m in compiled.finditer(text):
            matched = m.group(0)
            line_no = text[:m.start()].count("\n") + 1
            lower = matched.lower()
            fp = any(h.lower() in lower for h in pat["fp_hints"])
            results.append({
                "pattern_name": name,
                "matched": matched,
                "severity": pat["severity"],
                "line_no": line_no,
                "description": pat.get("description", name),
                "is_fp_hint": fp,
            })
    results.sort(key=lambda x: x["line_no"])
    return results


_scan_text = _load_scan_fn()

# ──────────────────────────────────────────────────────────────────────────────
# Gist streaming
# ──────────────────────────────────────────────────────────────────────────────

def stream_public_gists(max: int = 500, token: str = "") -> Iterator[dict]:
    """
    Yield raw gist dicts from GET /gists/public, paginated, up to `max` total.
    No token required. With token: uses the 5000 core req/h budget.
    Without token: uses the 60 req/h unauthenticated budget — avoid.
    """
    count = 0
    per_page = min(100, max)
    url: str | None = f"{GITHUB_API}/gists/public?per_page={per_page}"

    while url and count < max:
        try:
            body, hdrs = _get_json(url, token)
        except RuntimeError as e:
            logger.error("gist page fetch failed: %s", e)
            break

        if not isinstance(body, list):
            logger.warning("unexpected gist response type: %s", type(body))
            break

        for gist in body:
            if count >= max:
                return
            yield gist
            count += 1

        url = _parse_link_header(hdrs.get("Link")).get("next")


def _should_scan_file(filename: str, size: int) -> bool:
    """Decide whether to fetch+scan a gist file."""
    if size > 500_000:  # skip files >500KB
        return False
    name_lower = filename.lower()
    _, ext = os.path.splitext(name_lower)
    if ext in HIGH_VALUE_EXTS:
        return True
    # Check if base name (without ext) is in high value names
    base = name_lower.split(".")[0] if "." in name_lower else name_lower
    if any(hv in name_lower for hv in HIGH_VALUE_NAMES):
        return True
    # Also scan files with no extension (often scripts)
    if not ext:
        return True
    return False


def scan_gist(gist: dict, token: str = "") -> list[dict]:
    """
    Scan all files in a gist dict. Returns list of finding dicts.
    Files with truncated=True are fetched via raw_url (still public).
    """
    gist_id = gist.get("id", "")
    gist_html = gist.get("html_url", "")
    owner = (gist.get("owner") or {}).get("login", "anonymous")
    description = gist.get("description") or ""
    created_at = gist.get("created_at", "")
    updated_at = gist.get("updated_at", "")

    findings: list[dict] = []
    files: dict = gist.get("files") or {}

    for filename, file_info in files.items():
        size = file_info.get("size", 0) or 0
        raw_url = file_info.get("raw_url", "")
        language = file_info.get("language") or ""
        truncated = file_info.get("truncated", False)

        if not _should_scan_file(filename, size):
            logger.debug("skip %s/%s (size=%d, not high-value ext)", gist_id, filename, size)
            continue

        # Fetch content
        if not raw_url:
            continue

        content = _fetch_raw(raw_url)
        if not content:
            continue

        # Scan
        hits = _scan_text(content, filename)
        scanned_at = datetime.now(timezone.utc).isoformat()

        for hit in hits:
            findings.append({
                "source": "gist",
                "gist_id": gist_id,
                "gist_html_url": gist_html,
                "gist_owner": owner,
                "gist_description": description[:200],
                "gist_created_at": created_at,
                "gist_updated_at": updated_at,
                "filename": filename,
                "language": language,
                "raw_url": raw_url,
                "pattern_name": hit["pattern_name"],
                "matched_text": hit["matched"][:200],
                "severity": hit["severity"],
                "line_no": hit.get("line_no"),
                "description": hit.get("description", ""),
                "is_fp_hint": hit.get("is_fp_hint", False),
                "scanned_at": scanned_at,
            })

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Main hunt function
# ──────────────────────────────────────────────────────────────────────────────

def hunt_gists(
    max: int = 500,
    severity: str = "all",
    exclude_fp: bool = False,
    polite_delay: float = 0.1,
) -> list[dict]:
    """
    Stream public gists, scan each for secrets. Returns all findings.

    severity: "all" | "MEDIUM" | "HIGH" | "CRITICAL"
    polite_delay: seconds between raw file fetches (default 0.1s)
    """
    token = _load_token()
    if not token:
        logger.warning("No GITHUB_TOKEN; using unauthenticated calls (60 req/h — very limited)")

    _SEV_RANK = {"MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    min_rank = _SEV_RANK.get(severity.upper(), 0)

    all_findings: list[dict] = []
    gists_scanned = 0
    files_scanned = 0
    start = time.monotonic()

    logger.info("Starting gist hunt: max=%d severity=%s", max, severity)
    print(f"[gist_hunter] scanning up to {max} public gists...", file=sys.stderr)

    for gist in stream_public_gists(max=max, token=token):
        gists_scanned += 1
        n_files = len(gist.get("files") or {})
        files_scanned += n_files

        findings = scan_gist(gist, token=token)

        for f in findings:
            sev = f.get("severity", "MEDIUM")
            if _SEV_RANK.get(sev, 0) < min_rank:
                continue
            if exclude_fp and f.get("is_fp_hint"):
                continue
            all_findings.append(f)

        if gists_scanned % 50 == 0:
            elapsed = time.monotonic() - start
            print(
                f"[gist_hunter] {gists_scanned}/{max} gists | "
                f"{files_scanned} files | {len(all_findings)} findings | "
                f"{elapsed:.0f}s",
                file=sys.stderr,
            )

        if polite_delay > 0:
            time.sleep(polite_delay)

    elapsed = time.monotonic() - start
    logger.info(
        "hunt done: gists=%d files=%d findings=%d elapsed_ms=%d",
        gists_scanned, files_scanned, len(all_findings), int(elapsed * 1000),
    )
    print(
        f"[gist_hunter] done: {gists_scanned} gists, {files_scanned} files, "
        f"{len(all_findings)} findings ({elapsed:.0f}s)",
        file=sys.stderr,
    )
    return all_findings


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Scan public GitHub Gists for leaked secrets/API keys"
    )
    p.add_argument(
        "--max", type=int, default=500,
        help="Max gists to scan (API hard cap=3000). Default=500.",
    )
    p.add_argument(
        "--out", required=False,
        help="Output JSON path. Default: output/gists_<timestamp>.json",
    )
    p.add_argument(
        "--severity", choices=("all", "MEDIUM", "HIGH", "CRITICAL"), default="all",
        help="Minimum severity to include. Default=all.",
    )
    p.add_argument(
        "--exclude-fp", action="store_true",
        help="Exclude findings that match known false-positive hint strings.",
    )
    p.add_argument(
        "--delay", type=float, default=0.1,
        help="Seconds between raw file fetches (default=0.1). Increase to reduce rate-limit pressure.",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Print plan and exit without making API calls.",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    if args.dry_run:
        print(f"[dry-run] Would scan up to {args.max} public gists from GET /gists/public")
        print(f"[dry-run] severity>={args.severity}  exclude_fp={args.exclude_fp}  delay={args.delay}s")
        print(f"[dry-run] Output -> {args.out or 'output/gists_<timestamp>.json'}")
        print(f"[dry-run] Patterns: {len(_COMPILED)} inline fallback patterns")
        print("[dry-run] No API calls made.")
        return 0

    findings = hunt_gists(
        max=args.max,
        severity=args.severity,
        exclude_fp=args.exclude_fp,
        polite_delay=args.delay,
    )

    # Determine output path
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if args.out:
        out_path = Path(args.out)
        if not out_path.is_absolute():
            out_path = ROOT / out_path
    else:
        out_path = ROOT / "output" / f"gists_{ts}.json"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)

    print(f"wrote {len(findings)} findings -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
