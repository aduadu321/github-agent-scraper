#!/usr/bin/env python3
"""
GitHub search/scrape engine.

CLI:
    python scraper.py --query "ollama deploy" --kind repos --max 100 --out output/foo.json
    python scraper.py --query "FROM ollama" --kind code  --filename Modelfile --max 50 --out output/bar.json

Importable:
    from scraper import search
    rows = search("ollama deploy", kind="repos", max_results=100)
    rows = search("FROM llama", kind="code", filename="Modelfile", lang="dockerfile")

Stdlib only. Requires env var GITHUB_TOKEN (will also fall back to
C:\\Users\\aduad\\tools\\llm-rotate\\.env if not in os.environ).
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
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# --------------------------------------------------------------------------- #
# Paths / constants
# --------------------------------------------------------------------------- #

ROOT = Path(__file__).resolve().parent
LOG_DIR = ROOT / "logs"
LOG_FILE = LOG_DIR / "scraper.log"
ENV_FALLBACK = Path(r"C:\Users\aduad\tools\llm-rotate\.env")

GITHUB_API = "https://api.github.com"
API_VERSION = "2022-11-28"
USER_AGENT = "aduadu321-github-scraper/1.0"
SEARCH_HARD_CAP = 1000  # GitHub search API hard cap

LOG_DIR.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

logger = logging.getLogger("github_scraper")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s\t%(levelname)s\t%(message)s"))
    logger.addHandler(fh)
    # also echo warnings+ to stderr so the CLI user sees rate-limit pauses etc.
    sh = logging.StreamHandler()
    sh.setLevel(logging.WARNING)
    sh.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(sh)


# --------------------------------------------------------------------------- #
# Token loading
# --------------------------------------------------------------------------- #

def _load_token() -> str:
    tok = os.environ.get("GITHUB_TOKEN", "").strip()
    if tok:
        return tok
    # fallback: parse .env
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


# --------------------------------------------------------------------------- #
# HTTP layer
# --------------------------------------------------------------------------- #

class GitHubError(RuntimeError):
    def __init__(self, status: int, message: str, body: str = ""):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.body = body


def _build_headers(token: str) -> dict[str, str]:
    h = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": USER_AGENT,
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


_LINK_RE = re.compile(r'<([^>]+)>;\s*rel="([^"]+)"')


def _parse_link_header(link: str | None) -> dict[str, str]:
    if not link:
        return {}
    return {rel: url for url, rel in _LINK_RE.findall(link)}


def _sleep_for_rate_limit(headers: dict[str, str], status_summary: list[str]) -> None:
    """If remaining<2, sleep until reset+2s."""
    try:
        remaining = int(headers.get("X-RateLimit-Remaining", "999"))
        reset = int(headers.get("X-RateLimit-Reset", "0"))
    except ValueError:
        return
    if remaining < 2 and reset > 0:
        now = int(time.time())
        wait = max(1, reset - now + 2)
        logger.warning("Rate limit low (remaining=%d); sleeping %ds until reset", remaining, wait)
        status_summary.append(f"rl_sleep={wait}s")
        time.sleep(wait)


def _request(url: str, token: str, status_summary: list[str], max_attempts: int = 5) -> tuple[dict, dict[str, str]]:
    """
    Make one GET; return (json_body, response_headers).
    Honors 403/429 Retry-After and X-RateLimit-Reset. Raises GitHubError on 422 and other terminal failures.
    """
    req = urllib.request.Request(url, headers=_build_headers(token), method="GET")
    attempt = 0
    while True:
        attempt += 1
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                hdrs = {k: v for k, v in resp.headers.items()}
                status_summary.append(str(resp.status))
                body = json.loads(raw.decode("utf-8")) if raw else {}
                _sleep_for_rate_limit(hdrs, status_summary)
                return body, hdrs
        except urllib.error.HTTPError as e:
            hdrs = {k: v for k, v in (e.headers or {}).items()}
            body_text = ""
            try:
                body_text = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            status_summary.append(str(e.code))

            if e.code == 422:
                # invalid query — non-retryable
                logger.error("422 Unprocessable: %s", body_text[:500])
                raise GitHubError(422, "Unprocessable Entity (invalid query)", body_text)

            if e.code in (403, 429):
                # Retry-After or rate-limit reset
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
                if wait <= 0:
                    wait = 60
                if attempt >= max_attempts:
                    raise GitHubError(e.code, f"giving up after {attempt} attempts", body_text)
                logger.warning("HTTP %d; backing off %ds (attempt %d/%d)", e.code, wait, attempt, max_attempts)
                time.sleep(wait)
                continue

            if 500 <= e.code < 600 and attempt < max_attempts:
                wait = min(2 ** attempt, 30)
                logger.warning("HTTP %d server error; retrying in %ds", e.code, wait)
                time.sleep(wait)
                continue

            raise GitHubError(e.code, str(e), body_text)
        except urllib.error.URLError as e:
            if attempt >= max_attempts:
                raise GitHubError(0, f"network error: {e}", "")
            wait = min(2 ** attempt, 30)
            logger.warning("Network error %s; retrying in %ds", e, wait)
            time.sleep(wait)


# --------------------------------------------------------------------------- #
# Query construction
# --------------------------------------------------------------------------- #

def _build_q(query: str, kind: str, qualifiers: dict[str, str | None]) -> str:
    """Append qualifiers (lang/filename/extension) to the raw q string."""
    parts: list[str] = [query.strip()]
    lang = qualifiers.get("lang")
    filename = qualifiers.get("filename")
    extension = qualifiers.get("extension")
    if lang:
        # 'language:' works for both repo and code search
        parts.append(f"language:{lang}")
    if kind == "code":
        if filename:
            parts.append(f"filename:{filename}")
        if extension:
            parts.append(f"extension:{extension}")
    else:
        # for repos, filename/extension don't apply; warn quietly via logger
        if filename or extension:
            logger.info("filename/extension ignored for kind=repos")
    return " ".join(p for p in parts if p)


def _build_url(kind: str, q: str, per_page: int = 100) -> str:
    if kind == "repos":
        params = {"q": q, "sort": "stars", "order": "desc", "per_page": str(per_page)}
        path = "/search/repositories"
    elif kind == "code":
        params = {"q": q, "per_page": str(per_page)}
        path = "/search/code"
    else:
        raise ValueError(f"unknown kind: {kind}")
    return f"{GITHUB_API}{path}?{urllib.parse.urlencode(params)}"


# --------------------------------------------------------------------------- #
# Normalization
# --------------------------------------------------------------------------- #

def _norm_repo(item: dict) -> dict:
    lic = item.get("license") or {}
    return {
        "full_name": item.get("full_name"),
        "html_url": item.get("html_url"),
        "description": item.get("description"),
        "stargazers_count": item.get("stargazers_count"),
        "forks_count": item.get("forks_count"),
        "language": item.get("language"),
        "default_branch": item.get("default_branch"),
        "pushed_at": item.get("pushed_at"),
        "topics": item.get("topics") or [],
        "license": (lic.get("spdx_id") or lic.get("key")) if isinstance(lic, dict) else None,
    }


def _norm_code(item: dict, repo_cache: dict[str, dict]) -> dict:
    repo = item.get("repository") or {}
    full = repo.get("full_name")
    enriched = repo_cache.get(full, {}) if full else {}
    return {
        "repo_full_name": full,
        "path": item.get("path"),
        "html_url": item.get("html_url"),
        "sha": item.get("sha"),
        "score": item.get("score"),
        "repo_stars": enriched.get("stargazers_count"),
        "repo_pushed_at": enriched.get("pushed_at"),
    }


# --------------------------------------------------------------------------- #
# Repo enrichment for code search
# --------------------------------------------------------------------------- #

def _enrich_repos(full_names: Iterable[str], token: str, status_summary: list[str]) -> dict[str, dict]:
    """One GET /repos/{owner}/{repo} per unique repo; cached in-memory by caller."""
    out: dict[str, dict] = {}
    seen: set[str] = set()
    for fn in full_names:
        if not fn or fn in seen:
            continue
        seen.add(fn)
        url = f"{GITHUB_API}/repos/{fn}"
        try:
            body, _ = _request(url, token, status_summary)
            out[fn] = {
                "stargazers_count": body.get("stargazers_count"),
                "pushed_at": body.get("pushed_at"),
            }
        except GitHubError as e:
            logger.warning("enrich failed for %s: %s", fn, e)
            out[fn] = {"stargazers_count": None, "pushed_at": None}
    return out


# --------------------------------------------------------------------------- #
# Core search
# --------------------------------------------------------------------------- #

def search(
    query: str,
    kind: str = "repos",
    max_results: int = 100,
    **qualifiers: Any,
) -> list[dict]:
    """
    Run a GitHub search and return normalized rows.

    qualifiers: lang=..., filename=..., extension=...
    """
    if kind not in ("repos", "code"):
        raise ValueError("kind must be 'repos' or 'code'")
    token = _load_token()
    if kind == "code" and not token:
        raise RuntimeError("GITHUB_TOKEN required for code search")
    if not token:
        logger.warning("No GITHUB_TOKEN found; unauthenticated calls have a tiny quota")

    q = _build_q(query, kind, {
        "lang": qualifiers.get("lang"),
        "filename": qualifiers.get("filename"),
        "extension": qualifiers.get("extension"),
    })
    cap = min(int(max_results), SEARCH_HARD_CAP)
    url: str | None = _build_url(kind, q, per_page=min(100, cap))
    status_summary: list[str] = []
    start = time.monotonic()

    raw_items: list[dict] = []
    pages = 0
    while url and len(raw_items) < cap:
        body, hdrs = _request(url, token, status_summary)
        pages += 1
        items = body.get("items") or []
        if not items:
            break
        raw_items.extend(items)
        if len(raw_items) >= cap:
            break
        url = _parse_link_header(hdrs.get("Link")).get("next")

    raw_items = raw_items[:cap]

    if kind == "repos":
        rows = [_norm_repo(it) for it in raw_items]
    else:
        repo_names = [
            (it.get("repository") or {}).get("full_name")
            for it in raw_items
            if (it.get("repository") or {}).get("full_name")
        ]
        repo_cache = _enrich_repos(repo_names, token, status_summary) if repo_names else {}
        rows = [_norm_code(it, repo_cache) for it in raw_items]

    elapsed_ms = int((time.monotonic() - start) * 1000)
    logger.info(
        "query=%r\tkind=%s\tresults=%d\tpages=%d\thttp=%s\telapsed_ms=%d",
        query, kind, len(rows), pages, ",".join(status_summary), elapsed_ms,
    )
    return rows


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _write_output(rows: list[dict], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="GitHub search/scrape engine")
    p.add_argument("--query", required=True, help="raw search query")
    p.add_argument("--kind", choices=("repos", "code"), default="repos")
    p.add_argument("--max", dest="max_results", type=int, default=100,
                   help="cap on number of results (GitHub hard cap=1000)")
    p.add_argument("--out", required=False, help="output JSON path (required unless --dry-run)")
    p.add_argument("--lang", default=None, help="language qualifier (e.g. python)")
    p.add_argument("--filename", default=None, help="filename qualifier (code search only)")
    p.add_argument("--extension", default=None, help="extension qualifier (code search only)")
    p.add_argument("--dry-run", action="store_true", help="print URL and exit")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    q = _build_q(args.query, args.kind, {
        "lang": args.lang,
        "filename": args.filename,
        "extension": args.extension,
    })
    url = _build_url(args.kind, q, per_page=min(100, args.max_results))

    if args.dry_run:
        print(url)
        return 0

    if not args.out:
        print("ERROR: --out is required (unless --dry-run)", file=sys.stderr)
        return 2

    try:
        rows = search(
            args.query,
            kind=args.kind,
            max_results=args.max_results,
            lang=args.lang,
            filename=args.filename,
            extension=args.extension,
        )
    except GitHubError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1 if e.status != 422 else 22
    except Exception as e:
        logger.exception("unhandled error")
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = ROOT / out_path
    _write_output(rows, out_path)
    print(f"wrote {len(rows)} rows -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())


# --------------------------------------------------------------------------- #
# Commit search
# --------------------------------------------------------------------------- #

_COMMIT_DORK_QUERIES: list[str] = [
    "remove api key merge:false is:public",
    "accidentally committed merge:false is:public",
    "forgot to remove token merge:false is:public",
    "oops key merge:false is:public",
    "delete credentials merge:false is:public",
    "add credentials merge:false is:public",
    "do not share merge:false is:public",
    "leaked key merge:false is:public",
    "revoke token merge:false is:public",
    "hardcoded api key merge:false is:public",
    "secret exposed merge:false is:public",
    "my api key merge:false is:public",
    "test credentials merge:false is:public",
]


def _norm_commit(item: dict) -> dict:
    commit = item.get("commit") or {}
    author = commit.get("author") or {}
    committer = commit.get("committer") or {}
    repo = item.get("repository") or {}
    return {
        "sha": item.get("sha"),
        "message_preview": (commit.get("message") or "")[:300],
        "author_login": (item.get("author") or {}).get("login"),
        "author_name": author.get("name"),
        "author_date": author.get("date"),
        "committer_date": committer.get("date"),
        "repo_full_name": repo.get("full_name"),
        "repo_html_url": repo.get("html_url"),
        "commit_url": item.get("html_url"),
        "score": item.get("score"),
    }


def search_commits(query: str, max_results: int = 100) -> list[dict]:
    """
    Search GitHub commit messages.

    Uses GET /search/commits with the preview Accept header.
    Rate limit: 30 req/min (shared with repos/issues/users search).
    Requires GITHUB_TOKEN for higher quota, though endpoint itself doesn't require auth.

    Returns list of normalized commit dicts.
    """
    token = _load_token()
    cap = min(int(max_results), SEARCH_HARD_CAP)
    per_page = min(100, cap)

    params = {
        "q": query.strip(),
        "sort": "committer-date",
        "order": "desc",
        "per_page": str(per_page),
    }
    url: str | None = (
        f"{GITHUB_API}/search/commits?{urllib.parse.urlencode(params)}"
    )

    # Commit search requires a preview Accept header (still required as of 2025)
    extra_headers = {
        "Accept": "application/vnd.github.cloak-preview+json",
    }

    status_summary: list[str] = []
    start = time.monotonic()
    raw_items: list[dict] = []
    pages = 0

    # We need to make the request with extra headers. Monkey-patch _request
    # isn't clean, so we replicate a minimal loop here.
    while url and len(raw_items) < cap:
        req = urllib.request.Request(
            url,
            headers={
                **_build_headers(token),
                **extra_headers,
            },
            method="GET",
        )
        attempt = 0
        max_attempts = 5
        while True:
            attempt += 1
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    raw = resp.read()
                    hdrs = {k: v for k, v in resp.headers.items()}
                    status_summary.append(str(resp.status))
                    body = json.loads(raw.decode("utf-8")) if raw else {}
                    _sleep_for_rate_limit(hdrs, status_summary)
                    break
            except urllib.error.HTTPError as e:
                hdrs = {k: v for k, v in (e.headers or {}).items()}
                body_text = ""
                try:
                    body_text = e.read().decode("utf-8", errors="replace")
                except Exception:
                    pass
                status_summary.append(str(e.code))
                if e.code == 422:
                    logger.error("422 commit search: %s", body_text[:300])
                    raise GitHubError(422, "Unprocessable Entity", body_text)
                if e.code in (403, 429):
                    wait = 60
                    try:
                        reset = int(hdrs.get("X-RateLimit-Reset", "0"))
                        if reset > 0:
                            wait = max(1, reset - int(time.time()) + 2)
                    except ValueError:
                        pass
                    if attempt >= max_attempts:
                        raise GitHubError(e.code, f"giving up after {attempt} attempts", body_text)
                    logger.warning("HTTP %d; sleeping %ds", e.code, wait)
                    time.sleep(wait)
                    continue
                if 500 <= e.code < 600 and attempt < max_attempts:
                    time.sleep(min(2 ** attempt, 30))
                    continue
                raise GitHubError(e.code, str(e), body_text)
            except urllib.error.URLError as e:
                if attempt >= max_attempts:
                    raise GitHubError(0, f"network error: {e}", "")
                time.sleep(min(2 ** attempt, 30))

        pages += 1
        items = body.get("items") or []
        if not items:
            break
        raw_items.extend(items)
        if len(raw_items) >= cap:
            break
        url = _parse_link_header(hdrs.get("Link")).get("next")

    raw_items = raw_items[:cap]
    rows = [_norm_commit(it) for it in raw_items]

    elapsed_ms = int((time.monotonic() - start) * 1000)
    logger.info(
        "commit_search query=%r results=%d pages=%d http=%s elapsed_ms=%d",
        query, len(rows), pages, ",".join(status_summary), elapsed_ms,
    )
    return rows
