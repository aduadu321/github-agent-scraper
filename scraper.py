"""GitHub Search API wrapper.

search(q, kind, max_results, **qualifiers) -> list[dict]

kind: "repos" | "code"

Each result for repos includes: full_name, description, stars, language,
  topics, pushed_at, html_url, clone_url, default_branch

Each result for code includes: repo_full_name, path, html_url, raw_url,
  snippet (first 400 chars of file content)
"""
from __future__ import annotations

import base64
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import json
from typing import Any

API = "https://api.github.com"
USER_AGENT = "github-agent-scraper/2.0"
SNIPPET_CHARS = 400
RATE_PAUSE = 2.0          # seconds between paginated calls
CODE_CONTENT_PAUSE = 0.5  # seconds between content fetches


def _token() -> str:
    return (os.environ.get("GITHUB_TOKEN")
            or os.environ.get("GH_TOKEN")
            or "")


def _headers() -> dict[str, str]:
    h = {
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    tok = _token()
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def _get(url: str, params: dict | None = None) -> Any:
    if params:
        url = url + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers=_headers())
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {e.code} {url}: {body[:300]}") from e


def _build_q(q: str, qualifiers: dict) -> str:
    parts = [q]
    for k, v in qualifiers.items():
        parts.append(f"{k}:{v}")
    return " ".join(parts)


def _fetch_snippet(raw_url: str) -> str:
    try:
        req = urllib.request.Request(raw_url, headers=_headers())
        with urllib.request.urlopen(req, timeout=15) as r:
            data = r.read(SNIPPET_CHARS * 4)
        text = data.decode(errors="replace")
        return text[:SNIPPET_CHARS]
    except Exception:
        return ""


def _fetch_content_api(repo: str, path: str) -> str:
    url = f"{API}/repos/{repo}/contents/{urllib.parse.quote(path)}"
    try:
        data = _get(url)
        if isinstance(data, dict) and data.get("encoding") == "base64":
            raw = base64.b64decode(data["content"].replace("\n", ""))
            return raw.decode(errors="replace")[:SNIPPET_CHARS]
    except Exception:
        pass
    return ""


def search_repos(q: str, max_results: int, qualifiers: dict) -> list[dict]:
    full_q = _build_q(q, qualifiers)
    results = []
    page = 1
    while len(results) < max_results:
        per_page = min(30, max_results - len(results))
        try:
            data = _get(f"{API}/search/repositories", {
                "q": full_q,
                "sort": "stars",
                "order": "desc",
                "per_page": per_page,
                "page": page,
            })
        except RuntimeError as e:
            print(f"[scraper] repos error: {e}")
            break

        items = data.get("items", [])
        if not items:
            break

        for item in items:
            results.append({
                "full_name": item.get("full_name"),
                "description": item.get("description"),
                "stars": item.get("stargazers_count", 0),
                "language": item.get("language"),
                "topics": item.get("topics", []),
                "pushed_at": item.get("pushed_at"),
                "html_url": item.get("html_url"),
                "clone_url": item.get("clone_url"),
                "default_branch": item.get("default_branch", "main"),
                "open_issues": item.get("open_issues_count", 0),
                "license": (item.get("license") or {}).get("spdx_id"),
            })

        if len(items) < per_page:
            break
        page += 1
        time.sleep(RATE_PAUSE)

    return results


def search_code(q: str, max_results: int, qualifiers: dict,
                fetch_content: bool = True) -> list[dict]:
    full_q = _build_q(q, qualifiers)
    results = []
    page = 1
    while len(results) < max_results:
        per_page = min(30, max_results - len(results))
        try:
            data = _get(f"{API}/search/code", {
                "q": full_q,
                "per_page": per_page,
                "page": page,
            })
        except RuntimeError as e:
            print(f"[scraper] code error: {e}")
            break

        items = data.get("items", [])
        if not items:
            break

        for item in items:
            repo = item.get("repository", {})
            raw_url = (item.get("html_url", "")
                       .replace("github.com", "raw.githubusercontent.com")
                       .replace("/blob/", "/"))
            snippet = ""
            if fetch_content:
                snippet = _fetch_snippet(raw_url)
                time.sleep(CODE_CONTENT_PAUSE)

            results.append({
                "repo_full_name": repo.get("full_name"),
                "repo_description": repo.get("description"),
                "repo_stars": repo.get("stargazers_count"),
                "path": item.get("path"),
                "name": item.get("name"),
                "html_url": item.get("html_url"),
                "raw_url": raw_url,
                "snippet": snippet,
            })

        if len(items) < per_page:
            break
        page += 1
        time.sleep(RATE_PAUSE)

    return results


def search(q: str, kind: str = "repos", max_results: int = 30,
           fetch_content: bool = True, **qualifiers) -> list[dict]:
    if kind == "repos":
        return search_repos(q, max_results, qualifiers)
    elif kind == "code":
        return search_code(q, max_results, qualifiers, fetch_content=fetch_content)
    else:
        raise ValueError(f"unknown kind {kind!r}")
