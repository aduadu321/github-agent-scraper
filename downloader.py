"""GitHub downloader for the ollama/dolphin/REST-agent artifact scraper.

Reads a JSON file produced by `scraper.py` (repo-list or file-list mode) and
downloads only whitelisted high-signal files into
`downloads/<category>/<owner>__<repo>/<original-path>`.

Stdlib only. Concurrency capped at 6 workers (we share the 5000 req/h
budget with scraper.py).
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import fnmatch
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

API_ROOT = "https://api.github.com"
RAW_ROOT = "https://raw.githubusercontent.com"
USER_AGENT = "ar-scraper-downloader/1.0 (+local)"
MAX_WORKERS = 6
SIZE_CAP_BYTES = 256 * 1024
SIZE_CAP_EXEMPT = {"modelfile", "docker-compose.yml", "docker-compose.yaml", ".env.example"}

NAME_WHITELIST = {
    "modelfile",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    ".env",
    ".env.example",
    ".env.template",
    "requirements.txt",
    "pyproject.toml",
    "makefile",
    "install.sh",
    "setup.sh",
    "run.sh",
    "start.sh",
    "entrypoint.sh",
    "ollama.service",
}

PATH_GLOBS = [
    "**/agents/**/*.py",
    "**/agent*.py",
    "**/server.py",
    "**/api.py",
    "**/main.py",
    "**/*.modelfile",
    "**/scripts/*.sh",
    "**/scripts/*.ps1",
    "**/.github/workflows/*.yml",
]


# ---------------------------------------------------------------------------
# Token / env
# ---------------------------------------------------------------------------

def load_github_token() -> str | None:
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        return tok.strip()
    env_file = Path(r"C:\Users\aduad\tools\llm-rotate\.env")
    if env_file.exists():
        try:
            for line in env_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                k, _, v = line.partition("=")
                if k.strip() == "GITHUB_TOKEN":
                    return v.strip().strip('"').strip("'")
        except OSError:
            pass
    return None


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_LOCK = threading.Lock()
LOG_PATH = Path(r"C:\Users\aduad\tools\github-scraper\logs\downloader.log")


def log(msg: str) -> None:
    line = f"{datetime.now(timezone.utc).isoformat()} {msg}"
    with LOG_LOCK:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        print(line, flush=True)


# ---------------------------------------------------------------------------
# HTTP with rate-limit handling
# ---------------------------------------------------------------------------

RATE_LOCK = threading.Lock()
RATE_REMAINING = 5000
RATE_RESET_TS = 0.0


def _update_rate(headers) -> None:
    global RATE_REMAINING, RATE_RESET_TS
    try:
        rem = headers.get("X-RateLimit-Remaining")
        rst = headers.get("X-RateLimit-Reset")
        if rem is not None:
            with RATE_LOCK:
                RATE_REMAINING = int(rem)
        if rst is not None:
            with RATE_LOCK:
                RATE_RESET_TS = float(rst)
    except (TypeError, ValueError):
        pass


def _maybe_wait_for_reset() -> None:
    with RATE_LOCK:
        rem = RATE_REMAINING
        rst = RATE_RESET_TS
    if rem <= 1 and rst > 0:
        wait = max(0.0, rst - time.time()) + 1.0
        if wait > 0:
            log(f"ratelimit: sleeping {wait:.0f}s (remaining={rem})")
            time.sleep(min(wait, 900))  # cap 15 min


def http_get(url: str, token: str | None, accept: str = "application/vnd.github+json",
             max_retries: int = 4) -> tuple[int, dict, bytes]:
    """GET with auth, rate-limit awareness, and Retry-After honoring."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": accept,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    attempt = 0
    while True:
        _maybe_wait_for_reset()
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read()
                _update_rate(resp.headers)
                return resp.status, dict(resp.headers), body
        except urllib.error.HTTPError as e:
            _update_rate(e.headers or {})
            status = e.code
            retry_after = (e.headers or {}).get("Retry-After") if e.headers else None
            if status in (403, 429) and attempt < max_retries:
                wait = float(retry_after) if retry_after and retry_after.isdigit() else min(60 * (2 ** attempt), 300)
                log(f"http {status} on {url} — retry in {wait:.0f}s (attempt {attempt+1}/{max_retries})")
                time.sleep(wait)
                attempt += 1
                continue
            if status == 404:
                return status, dict(e.headers or {}), b""
            if attempt < max_retries:
                wait = min(5 * (2 ** attempt), 60)
                log(f"http {status} on {url} — backoff {wait}s")
                time.sleep(wait)
                attempt += 1
                continue
            log(f"http {status} on {url} — giving up")
            return status, dict(e.headers or {}), b""
        except urllib.error.URLError as e:
            if attempt < max_retries:
                wait = min(5 * (2 ** attempt), 60)
                log(f"urlerror {e} on {url} — backoff {wait}s")
                time.sleep(wait)
                attempt += 1
                continue
            log(f"urlerror {e} on {url} — giving up")
            return 0, {}, b""


# ---------------------------------------------------------------------------
# File filter
# ---------------------------------------------------------------------------

def path_is_wanted(path: str) -> bool:
    base = path.rsplit("/", 1)[-1].lower()
    if base in NAME_WHITELIST:
        return True
    # extension-style match for *.modelfile etc.
    p_lower = path.lower()
    for glob in PATH_GLOBS:
        if fnmatch.fnmatchcase(p_lower, glob.lower()):
            return True
    return False


def size_allowed(path: str, size: int | None) -> bool:
    base = path.rsplit("/", 1)[-1].lower()
    if base in SIZE_CAP_EXEMPT:
        return True
    if size is None:
        return True  # unknown — let it try, raw fetch will give actual bytes
    return size <= SIZE_CAP_BYTES


# ---------------------------------------------------------------------------
# Tree walk + downloads
# ---------------------------------------------------------------------------

def list_repo_tree(owner: str, repo: str, branch: str, token: str | None) -> list[dict]:
    url = f"{API_ROOT}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
    status, _, body = http_get(url, token)
    if status != 200 or not body:
        log(f"tree fetch failed {owner}/{repo}@{branch} status={status}")
        return []
    try:
        data = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        return []
    if data.get("truncated"):
        log(f"tree truncated for {owner}/{repo}@{branch} — will only see partial paths")
    return [e for e in data.get("tree", []) if e.get("type") == "blob"]


def file_sha_via_contents(owner: str, repo: str, path: str, branch: str,
                          token: str | None) -> str | None:
    """Get the blob SHA for a file via /contents/. Used for idempotency check
    when input is file-list mode (no tree fetched)."""
    url = f"{API_ROOT}/repos/{owner}/{repo}/contents/{path}?ref={branch}"
    status, _, body = http_get(url, token)
    if status != 200 or not body:
        return None
    try:
        data = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict):
        return data.get("sha")
    return None


def raw_download(owner: str, repo: str, branch: str, path: str,
                 token: str | None) -> bytes | None:
    url = f"{RAW_ROOT}/{owner}/{repo}/{branch}/{path}"
    status, _, body = http_get(url, token, accept="*/*")
    if status != 200:
        log(f"raw fetch failed {owner}/{repo}/{path} status={status}")
        return None
    return body


def contents_download(owner: str, repo: str, branch: str, path: str,
                      token: str | None) -> bytes | None:
    """Fallback: GET /repos/.../contents/{path} and base64-decode."""
    url = f"{API_ROOT}/repos/{owner}/{repo}/contents/{path}?ref={branch}"
    status, _, body = http_get(url, token)
    if status != 200 or not body:
        return None
    try:
        data = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    content_b64 = data.get("content")
    if not content_b64:
        return None
    try:
        return base64.b64decode(content_b64)
    except (ValueError, TypeError):
        return None


def write_file(target: Path, blob: bytes) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    # try utf-8 decode for sanity; fall back to binary
    try:
        text = blob.decode("utf-8")
        target.write_text(text, encoding="utf-8", newline="")
    except UnicodeDecodeError:
        target.write_bytes(blob)


def sha_matches_existing(target: Path, api_sha: str | None) -> bool:
    """GitHub blob sha = sha1('blob ' + len + '\\0' + content). We compare
    by recomputing on local bytes. Cheap and exact."""
    if not api_sha or not target.exists():
        return False
    import hashlib
    try:
        data = target.read_bytes()
    except OSError:
        return False
    header = f"blob {len(data)}\0".encode("utf-8")
    local = hashlib.sha1(header + data).hexdigest()
    return local == api_sha


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

MANIFEST_LOCK = threading.Lock()


def append_manifest(manifest_path: Path, entry: dict) -> None:
    with MANIFEST_LOCK:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        if manifest_path.exists():
            try:
                items = json.loads(manifest_path.read_text(encoding="utf-8"))
                if not isinstance(items, list):
                    items = []
            except (json.JSONDecodeError, OSError):
                items = []
        else:
            items = []
        items.append(entry)
        manifest_path.write_text(json.dumps(items, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

def process_file(owner: str, repo: str, branch: str, path: str,
                 size: int | None, sha: str | None,
                 out_root: Path, category: str, token: str | None) -> dict | None:
    if not path_is_wanted(path):
        return None
    if not size_allowed(path, size):
        log(f"skip:toobig {owner}/{repo}/{path} size={size}")
        return None

    repo_dir = out_root / f"{owner}__{repo}"
    target = repo_dir / path

    if sha and sha_matches_existing(target, sha):
        log(f"skip:exists {owner}/{repo}/{path}")
        return None

    blob = raw_download(owner, repo, branch, path, token)
    if blob is None:
        blob = contents_download(owner, repo, branch, path, token)
    if blob is None:
        log(f"fail {owner}/{repo}/{path}")
        return None

    # Re-check size against actual fetched bytes
    base = path.rsplit("/", 1)[-1].lower()
    if base not in SIZE_CAP_EXEMPT and len(blob) > SIZE_CAP_BYTES:
        log(f"skip:toobig-after-fetch {owner}/{repo}/{path} size={len(blob)}")
        return None

    write_file(target, blob)
    log(f"got {owner}/{repo}/{path} ({len(blob)} bytes) -> {target}")
    return {
        "repo": f"{owner}/{repo}",
        "path": path,
        "size_bytes": len(blob),
        "sha": sha,
        "downloaded_at_iso": datetime.now(timezone.utc).isoformat(),
        "category": category,
        "local_path": str(target),
    }


# ---------------------------------------------------------------------------
# Input mode detection
# ---------------------------------------------------------------------------

def detect_mode(items: list[dict]) -> str:
    if not items:
        return "empty"
    sample = items[0]
    if "full_name" in sample and "default_branch" in sample:
        return "repo-list"
    if "repo_full_name" in sample and "path" in sample:
        return "file-list"
    # tolerate full_name without default_branch — assume main
    if "full_name" in sample:
        return "repo-list"
    return "unknown"


def expand_repo_to_files(item: dict, token: str | None,
                         limit: int | None) -> list[tuple[str, str, str, str, int | None, str | None]]:
    full = item["full_name"]
    owner, _, repo = full.partition("/")
    branch = item.get("default_branch") or "main"
    tree = list_repo_tree(owner, repo, branch, token)
    out: list[tuple[str, str, str, str, int | None, str | None]] = []
    for entry in tree:
        p = entry.get("path")
        if not p:
            continue
        if not path_is_wanted(p):
            continue
        size = entry.get("size")
        sha = entry.get("sha")
        out.append((owner, repo, branch, p, size, sha))
        if limit is not None and len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="GitHub downloader (ollama/dolphin/agent artifacts).")
    ap.add_argument("--from", dest="src", required=True, help="Input JSON (scraper output).")
    ap.add_argument("--category", required=True, help="Folder name under downloads/.")
    ap.add_argument("--out", required=True, help="Output root (e.g. downloads/ollama/).")
    ap.add_argument("--limit", type=int, default=None, help="Max files to attempt (safety cap).")
    ap.add_argument("--workers", type=int, default=MAX_WORKERS, help="Thread pool size (default 6).")
    args = ap.parse_args()

    src = Path(args.src)
    if not src.exists():
        print(f"input not found: {src}", file=sys.stderr)
        return 2

    try:
        items = json.loads(src.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        print(f"cannot parse {src}: {e}", file=sys.stderr)
        return 2
    if not isinstance(items, list):
        print(f"expected JSON list at top level of {src}", file=sys.stderr)
        return 2

    token = load_github_token()
    if not token:
        log("warning: no GITHUB_TOKEN found — running unauthenticated (60 req/h)")

    mode = detect_mode(items)
    log(f"start: src={src} mode={mode} count={len(items)} category={args.category} out={args.out}")

    out_root = Path(args.out)
    out_root.mkdir(parents=True, exist_ok=True)
    manifest_path = out_root / "_manifest.json"

    tasks: list[tuple[str, str, str, str, int | None, str | None]] = []

    if mode == "repo-list":
        for item in items:
            if not isinstance(item, dict) or "full_name" not in item:
                continue
            remaining = None if args.limit is None else max(0, args.limit - len(tasks))
            if remaining == 0:
                break
            expanded = expand_repo_to_files(item, token, remaining)
            tasks.extend(expanded)
    elif mode == "file-list":
        for item in items:
            if not isinstance(item, dict):
                continue
            full = item.get("repo_full_name") or item.get("full_name")
            path = item.get("path")
            if not full or not path:
                continue
            owner, _, repo = full.partition("/")
            branch = item.get("default_branch") or item.get("branch") or "main"
            if not path_is_wanted(path):
                continue
            size = item.get("size")
            sha = item.get("sha")
            tasks.append((owner, repo, branch, path, size, sha))
            if args.limit is not None and len(tasks) >= args.limit:
                break
    else:
        log(f"unknown input mode for {src}; first item keys: {list(items[0].keys()) if items else []}")
        return 2

    log(f"queued {len(tasks)} candidate file(s)")

    written = 0
    with cf.ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futures = [
            ex.submit(process_file, owner, repo, branch, path, size, sha,
                      out_root, args.category, token)
            for (owner, repo, branch, path, size, sha) in tasks
        ]
        for fut in cf.as_completed(futures):
            try:
                entry = fut.result()
            except Exception as e:  # noqa: BLE001
                log(f"worker exception: {e}")
                continue
            if entry:
                append_manifest(manifest_path, entry)
                written += 1

    log(f"done: wrote {written} file(s); manifest={manifest_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
