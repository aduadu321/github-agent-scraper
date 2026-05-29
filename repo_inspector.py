"""repo_inspector.py — reads key files inside repos and extracts useful data.

For each repo in a MERGED.json, fetches:
  - README (first 1000 chars)
  - docker-compose.yml / .env.example / requirements.txt / Modelfile (first 2000 chars)

Extracts patterns:
  - API endpoints (http/https URLs)
  - Environment variable names
  - Port numbers
  - Model names

CLI:
    python repo_inspector.py --input output/public_apis__MERGED.json
    python repo_inspector.py --input output/public_apis__MERGED.json --top 50
    python repo_inspector.py --input output/ollama_deploy__MERGED.json --out output/inspected_ollama.json
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

API = "https://api.github.com"
USER_AGENT = "github-agent-scraper/2.0"
RATE_PAUSE = 0.3

KEY_FILES = [
    "README.md", "readme.md", "README", "README.rst",
    "docker-compose.yml", "docker-compose.yaml", "compose.yml",
    ".env.example", ".env.template", ".env.sample",
    "requirements.txt", "Modelfile", "install.sh", "setup.sh",
]

URL_RE = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
ENV_VAR_RE = re.compile(r'\b([A-Z][A-Z0-9_]{3,})\s*[=:]', re.MULTILINE)
PORT_RE = re.compile(r':\s*(\d{2,5})\b')
MODEL_RE = re.compile(r'(?:model|MODEL|FROM)\s*[=:"\s]+([a-z][a-z0-9._/-]+)', re.IGNORECASE)


def _token() -> str:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""


def _headers() -> dict:
    h = {
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    tok = _token()
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def _get_content(repo: str, path: str, max_chars: int = 2000) -> str:
    url = f"{API}/repos/{repo}/contents/{urllib.parse.quote(path)}"
    req = urllib.request.Request(url, headers=_headers())
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        if isinstance(data, dict) and data.get("encoding") == "base64":
            raw = base64.b64decode(data["content"].replace("\n", ""))
            return raw.decode(errors="replace")[:max_chars]
    except Exception:
        pass
    return ""


def _list_tree(repo: str, branch: str = "main") -> list[str]:
    for b in (branch, "master", "main"):
        url = f"{API}/repos/{repo}/git/trees/{b}?recursive=1"
        req = urllib.request.Request(url, headers=_headers())
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
            return [t["path"] for t in data.get("tree", []) if t.get("type") == "blob"]
        except Exception:
            continue
    return []


def extract_patterns(text: str) -> dict:
    urls = list(set(URL_RE.findall(text)))[:20]
    env_vars = list(set(ENV_VAR_RE.findall(text)))[:30]
    ports = list(set(PORT_RE.findall(text)))[:10]
    models = list(set(MODEL_RE.findall(text)))[:10]
    return {
        "urls": [u for u in urls if len(u) < 120],
        "env_vars": sorted(env_vars),
        "ports": sorted(set(p for p in ports if 1000 < int(p) < 65000)),
        "models": [m for m in models if len(m) < 60],
    }


def inspect_repo(repo_item: dict) -> dict:
    repo = repo_item.get("full_name") or repo_item.get("repo_full_name", "")
    branch = repo_item.get("default_branch", "main")
    result = {
        "repo": repo,
        "stars": repo_item.get("stars") or repo_item.get("stargazers_count", 0),
        "description": repo_item.get("description", ""),
        "html_url": repo_item.get("html_url", ""),
        "files_found": [],
        "patterns": {"urls": [], "env_vars": [], "ports": [], "models": []},
    }

    all_text = ""
    tree = _list_tree(repo, branch)
    time.sleep(RATE_PAUSE)

    found_paths = []
    for kf in KEY_FILES:
        kf_lower = kf.lower()
        match = next((p for p in tree if p.lower() == kf_lower or
                      p.lower().endswith("/" + kf_lower)), None)
        if match:
            found_paths.append(match)

    for path in found_paths[:5]:
        content = _get_content(repo, path)
        time.sleep(RATE_PAUSE)
        if content:
            result["files_found"].append({
                "path": path,
                "preview": content[:500],
            })
            all_text += content + "\n"

    if all_text:
        result["patterns"] = extract_patterns(all_text)

    return result


def run(input_path: str, top: int, out_path: str | None) -> None:
    data = json.loads(Path(input_path).read_text(encoding="utf-8"))
    items = data.get("results", data) if isinstance(data, dict) else data

    items_sorted = sorted(items, key=lambda x: x.get("stars") or x.get("stargazers_count", 0),
                          reverse=True)[:top]

    print(f"[inspector] Inspecting {len(items_sorted)} repos from {input_path}")

    results = []
    for i, item in enumerate(items_sorted, 1):
        repo = item.get("full_name") or item.get("repo_full_name", "unknown")
        print(f"  [{i}/{len(items_sorted)}] {repo}")
        try:
            r = inspect_repo(item)
            results.append(r)
        except Exception as e:
            print(f"    ERROR: {e}")

    out = out_path or input_path.replace(".json", "__inspected.json")
    Path(out).write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[inspector] Done. {len(results)} repos inspected -> {out}")

    print("\n=== TOP FINDINGS ===")
    for r in results[:10]:
        if r["files_found"] or r["patterns"]["env_vars"]:
            print(f"\n  {r['repo']} ({r['stars']}★)")
            if r["files_found"]:
                for f in r["files_found"]:
                    print(f"    FILE: {f['path']}")
                    print(f"    {f['preview'][:200].strip()}")
            if r["patterns"]["env_vars"]:
                print(f"    ENV VARS: {', '.join(r['patterns']['env_vars'][:8])}")
            if r["patterns"]["ports"]:
                print(f"    PORTS: {', '.join(r['patterns']['ports'])}")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", required=True, help="MERGED.json from scraper")
    p.add_argument("--top", type=int, default=30, help="top N repos by stars")
    p.add_argument("--out", help="output JSON path")
    args = p.parse_args()
    run(args.input, args.top, args.out)


if __name__ == "__main__":
    main()
