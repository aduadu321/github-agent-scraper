#!/usr/bin/env python3
"""
GitHub commit-history secret scanner.

Scans commit history for secrets that were committed then deleted.
GitHub API exposes full diffs even for removed lines — this tool mines them.

CLI:
    python git_history_scan.py --repo owner/repo
                               [--since 2024-01-01]
                               [--max-commits 200]
                               [--out output/history_REPO.json]
                               [--dry-run]

    python git_history_scan.py --from-file output/repos.json
                               [--top 10]
                               [--since 2024-01-01]
                               [--max-commits 200]
                               [--out output/history_batch.json]
                               [--dry-run]

Stdlib only. Token: env GITHUB_TOKEN or parsed from C:\\Users\\aduad\\tools\\llm-rotate\\.env.
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
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent
LOG_DIR = ROOT / "logs"
OUTPUT_DIR = ROOT / "output"
LOG_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("git_history_scan")
if not logger.handlers:
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler(LOG_DIR / "git_history_scan.log", encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s\t%(levelname)s\t%(message)s"))
    logger.addHandler(fh)
    sh = logging.StreamHandler()
    sh.setLevel(logging.WARNING)
    sh.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(sh)

# ---------------------------------------------------------------------------
# Inline FALLBACK_PATTERNS — same as hunt_secrets.py
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
    "groq": {
        "regex": r"gsk_[a-zA-Z0-9]{50,60}",
        "severity": "HIGH",
        "false_positive_hints": ["gsk_xxxx"],
    },
}

# Compiled once at module load
_COMPILED: list[tuple[str, re.Pattern, str, list[str]]] = [
    (name, re.compile(pat["regex"]), pat["severity"], pat.get("false_positive_hints", []))
    for name, pat in FALLBACK_PATTERNS.items()
]

# Secret-relevant filename patterns (basename match, case-insensitive)
SECRET_FILENAME_PATTERNS: list[re.Pattern] = [
    re.compile(r"^\.env"),                        # .env, .env.local, .env.production
    re.compile(r"^\.envrc$"),
    re.compile(r"secrets?\.ya?ml$"),
    re.compile(r"secrets?\.json$"),
    re.compile(r"credentials?\.ya?ml$"),
    re.compile(r"credentials?\.json$"),
    re.compile(r"config\.ya?ml$"),
    re.compile(r"config\.json$"),
    re.compile(r"settings\.py$"),
    re.compile(r"settings_local\.py$"),
    re.compile(r"local_settings\.py$"),
    re.compile(r"\.py$"),
    re.compile(r"\.sh$"),
    re.compile(r"\.ya?ml$"),
    re.compile(r"^Modelfile$"),
    re.compile(r"^makefile$"),
    re.compile(r"\.ini$"),
    re.compile(r"\.cfg$"),
    re.compile(r"\.conf$"),
    re.compile(r"\.toml$"),
]

# ---------------------------------------------------------------------------
# Token loader
# ---------------------------------------------------------------------------

_ENV_FALLBACK = Path(r"C:\Users\aduad\tools\llm-rotate\.env")


def _load_token() -> str:
    tok = os.environ.get("GITHUB_TOKEN", "").strip()
    if tok:
        return tok
    if _ENV_FALLBACK.exists():
        try:
            for raw in _ENV_FALLBACK.read_text(encoding="utf-8", errors="replace").splitlines():
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
# HTTP helpers
# ---------------------------------------------------------------------------

USER_AGENT = "aduadu321-git-history-scan/1.0"
API_BASE = "https://api.github.com"


def _api_get(path: str, token: str, params: dict[str, str] | None = None) -> tuple[Any, dict]:
    """
    GET {API_BASE}{path}?{params}.
    Returns (parsed_json, response_headers_dict).
    Raises urllib.error.HTTPError on non-2xx.
    """
    url = f"{API_BASE}{path}"
    if params:
        qs = "&".join(f"{k}={urllib.request.quote(str(v))}" for k, v in params.items())
        url = f"{url}?{qs}"

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        resp_headers = dict(resp.headers)
        return json.loads(body), resp_headers


def _rate_check(headers: dict) -> None:
    """Sleep if core rate limit is near exhaustion."""
    remaining = int(headers.get("X-Ratelimit-Remaining", headers.get("x-ratelimit-remaining", "999")))
    reset_ts = int(headers.get("X-Ratelimit-Reset", headers.get("x-ratelimit-reset", "0")))
    if remaining <= 5 and reset_ts:
        wait = max(reset_ts - int(time.time()), 0) + 2
        logger.warning("Rate limit near exhaustion (%d remaining) — sleeping %ds", remaining, wait)
        print(f"  [rate-limit] {remaining} remaining, sleeping {wait}s …", flush=True)
        time.sleep(wait)


def _get_with_retry(path: str, token: str, params: dict[str, str] | None = None,
                    retries: int = 4) -> tuple[Any, dict]:
    """Wrapper around _api_get with retry on 429/5xx."""
    for attempt in range(1, retries + 1):
        try:
            data, hdrs = _api_get(path, token, params)
            _rate_check(hdrs)
            return data, hdrs
        except urllib.error.HTTPError as e:
            if e.code == 429:
                retry_after = int(e.headers.get("Retry-After", "60"))
                logger.warning("429 on %s — sleeping %ds", path, retry_after)
                time.sleep(retry_after)
                continue
            if e.code == 403:
                # May be rate-limit secondary
                try:
                    body = e.read().decode("utf-8", errors="replace")
                except Exception:
                    body = ""
                if "rate limit" in body.lower() or "secondary" in body.lower():
                    wait = 60 * attempt
                    logger.warning("403 rate-limit on %s — sleeping %ds", path, wait)
                    time.sleep(wait)
                    continue
                raise
            if 500 <= e.code < 600 and attempt < retries:
                time.sleep(2 ** attempt)
                continue
            raise
        except Exception:
            if attempt < retries:
                time.sleep(2 ** attempt)
                continue
            raise
    raise RuntimeError(f"Exhausted retries for {path}")


# ---------------------------------------------------------------------------
# Filename relevance check
# ---------------------------------------------------------------------------

def _is_secret_relevant(filepath: str) -> bool:
    basename = Path(filepath).name.lower()
    for pat in SECRET_FILENAME_PATTERNS:
        if pat.search(basename):
            return True
    return False


# ---------------------------------------------------------------------------
# Secret scanning of deleted lines
# ---------------------------------------------------------------------------

def _mask(s: str, keep: int = 6) -> str:
    """Mask middle of a secret string for safe logging."""
    if len(s) <= keep * 2:
        return s[:keep] + "***"
    return s[:keep] + "..." + s[-keep:]


def _scan_deleted_lines(patch: str) -> list[dict]:
    """
    Given a unified diff patch string, extract lines starting with '-'
    (deleted lines, excluding --- header lines) and scan for secrets.
    Returns list of finding dicts.
    """
    hits: list[dict] = []
    for line in patch.splitlines():
        if not line.startswith("-"):
            continue
        if line.startswith("---"):
            continue
        content = line[1:]  # strip leading '-'
        for name, compiled, severity, fp_hints in _COMPILED:
            for m in compiled.finditer(content):
                matched = m.group(0)
                is_fp = any(h.lower() in matched.lower() for h in fp_hints if h)
                if is_fp:
                    continue
                hits.append({
                    "pattern_name": name,
                    "severity": severity,
                    "matched_text": _mask(matched),
                    "deleted_line": content.strip(),
                })
    return hits


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

def scan_repo(
    repo: str,
    token: str,
    since: str | None = None,
    max_commits: int = 200,
    dry_run: bool = False,
) -> list[dict]:
    """
    Scan one repo's commit history for deleted secrets.
    Returns list of finding dicts.
    """
    findings: list[dict] = []

    if dry_run:
        since_display = since or "(no since filter)"
        print(f"  DRY-RUN  repo={repo}  since={since_display}  max-commits={max_commits}")
        print(f"  Would call: GET /repos/{repo}/commits?per_page=100[&since={since or ''}]")
        print(f"  Then GET /repos/{repo}/commits/<sha> for each commit (up to {max_commits})")
        return []

    # ---- 1. Paginate commit list -------------------------------------------
    commits: list[dict] = []
    page = 1
    while len(commits) < max_commits:
        params: dict[str, str] = {"per_page": "100", "page": str(page)}
        if since:
            params["since"] = since

        try:
            data, hdrs = _get_with_retry(f"/repos/{repo}/commits", token, params)
        except urllib.error.HTTPError as e:
            logger.error("Failed to list commits for %s: HTTP %d", repo, e.code)
            print(f"  [ERROR] listing commits for {repo}: HTTP {e.code}", flush=True)
            break
        except Exception as e:
            logger.error("Failed to list commits for %s: %s", repo, e)
            print(f"  [ERROR] listing commits for {repo}: {e}", flush=True)
            break

        if not data:
            break

        commits.extend(data)
        if len(data) < 100:
            break  # last page
        page += 1

    commits = commits[:max_commits]
    logger.info("repo=%s commits_fetched=%d", repo, len(commits))
    print(f"  {repo}: {len(commits)} commits to inspect", flush=True)

    # ---- 2. Per-commit detail -----------------------------------------------
    for idx, commit_meta in enumerate(commits, 1):
        sha: str = commit_meta.get("sha", "")
        if not sha:
            continue

        commit_date: str = ""
        author_login: str = ""
        try:
            cd = commit_meta.get("commit", {}).get("author", {}).get("date", "")
            commit_date = cd
            al = (commit_meta.get("author") or {}).get("login", "")
            if not al:
                al = commit_meta.get("commit", {}).get("author", {}).get("name", "anon")
            # Anonymize: first 3 chars + ***
            author_masked = al[:3] + "***" if len(al) >= 3 else al + "***"
        except Exception:
            author_masked = "unk***"

        try:
            detail, hdrs = _get_with_retry(f"/repos/{repo}/commits/{sha}", token)
        except urllib.error.HTTPError as e:
            logger.warning("commit detail %s/%s HTTP %d — skip", repo, sha, e.code)
            time.sleep(0.2)
            continue
        except Exception as e:
            logger.warning("commit detail %s/%s error: %s — skip", repo, sha, e)
            time.sleep(0.2)
            continue

        files: list[dict] = detail.get("files", []) or []
        commit_url = f"https://github.com/{repo}/commit/{sha}"

        for f in files:
            status: str = f.get("status", "")
            if status not in ("removed", "modified"):
                continue

            filepath: str = f.get("filename", "") or f.get("previous_filename", "")
            if not filepath:
                continue
            if not _is_secret_relevant(filepath):
                continue

            patch: str = f.get("patch", "") or ""
            if not patch:
                continue

            hits = _scan_deleted_lines(patch)
            for hit in hits:
                finding: dict = {
                    "repo": repo,
                    "commit_sha": sha,
                    "commit_date": commit_date,
                    "author_masked": author_masked,
                    "file_path": filepath,
                    "file_status": status,
                    "deleted_line": hit["deleted_line"],
                    "pattern_name": hit["pattern_name"],
                    "severity": hit["severity"],
                    "matched_text": hit["matched_text"],
                    "commit_url": commit_url,
                }
                findings.append(finding)
                print(
                    f"  [{hit['severity']}] {repo}  {filepath}  "
                    f"pattern={hit['pattern_name']}  sha={sha[:8]}  "
                    f"matched={hit['matched_text']}",
                    flush=True,
                )
                logger.info(
                    "FINDING repo=%s sha=%s file=%s pattern=%s severity=%s",
                    repo, sha[:8], filepath, hit["pattern_name"], hit["severity"],
                )

        # Polite sleep between commit-detail calls (spec: 0.2s)
        time.sleep(0.2)

        if idx % 20 == 0:
            print(f"  … {idx}/{len(commits)} commits scanned", flush=True)

    logger.info("repo=%s findings=%d", repo, len(findings))
    return findings


# ---------------------------------------------------------------------------
# Batch mode: --from-file
# ---------------------------------------------------------------------------

def load_repos_from_file(path: Path, top: int) -> list[str]:
    """
    Load repos from a scraper output JSON (list of dicts with 'full_name').
    Sort by stargazers_count desc, return top N full_names.
    """
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"Expected JSON array in {path}")

    # Support both repo-list format (full_name) and flat list of strings
    repos: list[tuple[int, str]] = []
    for item in raw:
        if isinstance(item, str):
            repos.append((0, item))
        elif isinstance(item, dict):
            name = item.get("full_name") or item.get("repo_full_name") or ""
            stars = int(item.get("stargazers_count") or item.get("repo_stars") or 0)
            if name:
                repos.append((stars, name))

    repos.sort(key=lambda t: t[0], reverse=True)
    return [name for _, name in repos[:top]]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Scan GitHub commit history for secrets deleted from files"
    )

    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("--repo", metavar="OWNER/REPO", help="Single repo to scan")
    target.add_argument(
        "--from-file",
        metavar="PATH",
        dest="from_file",
        help="Scraper output JSON; scans top N repos sorted by stars",
    )

    p.add_argument(
        "--top",
        type=int,
        default=10,
        help="(--from-file) How many repos to scan. Default: 10",
    )
    p.add_argument(
        "--since",
        default=None,
        metavar="YYYY-MM-DD",
        help="Only commits after this date (ISO 8601). Default: no filter",
    )
    p.add_argument(
        "--max-commits",
        dest="max_commits",
        type=int,
        default=200,
        help="Max commits to inspect per repo. Default: 200",
    )
    p.add_argument(
        "--out",
        default=None,
        metavar="PATH",
        help="Output JSON file. Default: output/history_<REPO|batch>_<ts>.json",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Print plan and exit 0 — no API calls made",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    token = _load_token()

    if not token and not args.dry_run:
        print("[WARN] No GITHUB_TOKEN found — unauthenticated (60 req/h limit applies)", flush=True)

    # ---- Resolve repo list -------------------------------------------------
    if args.repo:
        repos = [args.repo.strip()]
        default_label = args.repo.replace("/", "_")
    else:
        from_path = Path(args.from_file)
        if not from_path.exists():
            print(f"[ERROR] --from-file path not found: {from_path}", file=sys.stderr)
            return 1
        repos = load_repos_from_file(from_path, args.top)
        default_label = "batch"
        print(f"Loaded {len(repos)} repos from {from_path} (top={args.top})", flush=True)
        for r in repos:
            print(f"  {r}", flush=True)

    # ---- Output path -------------------------------------------------------
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if args.out:
        out_path = Path(args.out)
        if not out_path.is_absolute():
            out_path = ROOT / out_path
    else:
        out_path = OUTPUT_DIR / f"history_{default_label}_{ts}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # ---- Dry-run -----------------------------------------------------------
    if args.dry_run:
        since_display = args.since or "(no since filter)"
        print(f"\n{'='*60}")
        print(f"DRY-RUN — git_history_scan plan")
        print(f"{'='*60}")
        print(f"  Repos         : {len(repos)}")
        print(f"  Since         : {since_display}")
        print(f"  Max commits   : {args.max_commits}")
        print(f"  Output        : {out_path}")
        print(f"  Token present : {'yes' if token else 'NO (will fail for private repos)'}")
        print(f"  Patterns      : {', '.join(FALLBACK_PATTERNS)}")
        print()
        for repo in repos:
            scan_repo(repo, token, args.since, args.max_commits, dry_run=True)
        print("\n0 API calls made.")
        return 0

    # ---- Live scan ---------------------------------------------------------
    all_findings: list[dict] = []
    for i, repo in enumerate(repos, 1):
        print(f"\n[{i}/{len(repos)}] Scanning {repo} …", flush=True)
        try:
            findings = scan_repo(
                repo=repo,
                token=token,
                since=args.since,
                max_commits=args.max_commits,
                dry_run=False,
            )
            all_findings.extend(findings)
        except Exception as e:
            logger.error("Unhandled error scanning %s: %s", repo, e)
            print(f"  [ERROR] {repo}: {e}", flush=True)

    # ---- Write output ------------------------------------------------------
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(all_findings, f, ensure_ascii=False, indent=2)

    print(f"\n{'='*60}", flush=True)
    print(f"Total findings : {len(all_findings)}", flush=True)
    print(f"Output         : {out_path}", flush=True)
    logger.info("scan complete findings=%d output=%s", len(all_findings), out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
