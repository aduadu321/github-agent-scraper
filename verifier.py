"""verifier.py — checks if found repos and API endpoints are actually live.

For repos:  HEAD request to html_url -> UP / DOWN / PRIVATE
For APIs:   GET to extracted URLs, checks HTTP 200/401/403 (alive) vs 404/5xx (dead)
For docker: checks if image exists on Docker Hub

CLI:
    python verifier.py --input output/public_apis__MERGED__inspected.json
    python verifier.py --input output/ollama_deploy__MERGED__inspected.json --workers 10
    python verifier.py --input output/public_apis__MERGED.json --no-inspect
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

TIMEOUT = 8
MAX_WORKERS = 8
DOCKER_HUB = "https://hub.docker.com/v2/repositories"

SKIP_DOMAINS = {
    "github.com", "raw.githubusercontent.com", "shields.io",
    "img.shields.io", "badge.fury.io", "travis-ci.org",
    "circleci.com", "codecov.io", "npmjs.com",
}

API_URL_RE = re.compile(
    r'https?://(?!github\.com|raw\.githubusercontent\.com|shields\.io)'
    r'[^\s"\'<>)]+(?:/api|/v\d|/graphql|/rest|:\d{4,5})[^\s"\'<>)]*',
    re.IGNORECASE
)

DOCKER_IMAGE_RE = re.compile(
    r'image:\s*([a-z0-9_.-]+(?:/[a-z0-9_.-]+)?(?::[a-z0-9_.-]+)?)',
    re.IGNORECASE | re.MULTILINE
)


def _req(url: str, method: str = "GET") -> tuple[int, str]:
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "github-agent-scraper/2.0"},
            method=method,
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, "OK"
    except urllib.error.HTTPError as e:
        return e.code, e.reason
    except Exception as e:
        return 0, str(e)[:80]


def _classify(status: int) -> str:
    if status in (200, 201, 204, 301, 302):
        return "UP"
    if status in (401, 403):
        return "UP_AUTH"   # alive but needs auth
    if status in (404, 410):
        return "DOWN"
    if status == 429:
        return "RATE_LIMITED"
    if status >= 500:
        return "SERVER_ERROR"
    if status == 0:
        return "UNREACHABLE"
    return f"HTTP_{status}"


def check_repo(item: dict) -> dict:
    repo = item.get("repo") or item.get("full_name", "")
    url = item.get("html_url") or f"https://github.com/{repo}"
    status, reason = _req(url, method="HEAD")
    result = _classify(status)
    return {
        "repo": repo,
        "stars": item.get("stars", 0),
        "url": url,
        "status": result,
        "http": status,
        "description": item.get("description", ""),
    }


def check_api_url(url: str) -> dict:
    try:
        domain = urllib.parse.urlparse(url).netloc
    except ValueError:
        return {"url": url, "status": "SKIPPED", "http": 0}
    if any(s in domain for s in SKIP_DOMAINS):
        return {"url": url, "status": "SKIPPED", "http": 0}
    status, reason = _req(url)
    return {
        "url": url,
        "domain": domain,
        "status": _classify(status),
        "http": status,
        "reason": reason,
    }


def check_docker_image(image: str) -> dict:
    image = image.strip()
    if "/" not in image:
        image = f"library/{image}"
    tag = "latest"
    if ":" in image.split("/")[-1]:
        parts = image.rsplit(":", 1)
        image, tag = parts[0], parts[1]
    url = f"{DOCKER_HUB}/{image}/tags/{tag}"
    status, _ = _req(url)
    return {
        "image": f"{image}:{tag}",
        "status": "EXISTS" if status == 200 else "NOT_FOUND" if status == 404 else f"HTTP_{status}",
    }


def extract_api_urls(items: list[dict]) -> list[str]:
    urls = set()
    for item in items:
        for f in item.get("files_found", []):
            found = API_URL_RE.findall(f.get("preview", ""))
            urls.update(found[:5])
        for u in item.get("patterns", {}).get("urls", []):
            if API_URL_RE.match(u):
                urls.add(u)
    return list(urls)[:100]


def extract_docker_images(items: list[dict]) -> list[str]:
    images = set()
    for item in items:
        for f in item.get("files_found", []):
            found = DOCKER_IMAGE_RE.findall(f.get("preview", ""))
            images.update(found)
    return list(images)[:50]


def run(input_path: str, workers: int, out_path: str | None) -> None:
    data = json.loads(Path(input_path).read_text(encoding="utf-8"))

    # support both inspected (list) and MERGED (dict with results key)
    if isinstance(data, dict):
        items = data.get("results", [])
    else:
        items = data

    print(f"[verifier] {len(items)} items from {input_path}")

    # ── 1. check repos ────────────────────────────────────────────────────────
    print(f"\n[verifier] checking {len(items)} repos ({workers} workers)...")
    repo_results = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(check_repo, item): item for item in items}
        for i, fut in enumerate(cf.as_completed(futs), 1):
            r = fut.result()
            repo_results.append(r)
            if i % 10 == 0 or i == len(items):
                up = sum(1 for x in repo_results if x["status"] in ("UP", "UP_AUTH"))
                print(f"  [{i}/{len(items)}] UP: {up}")

    up_repos = [r for r in repo_results if r["status"] in ("UP", "UP_AUTH")]
    down_repos = [r for r in repo_results if r["status"] == "DOWN"]
    print(f"\n  Repos UP: {len(up_repos)} / DOWN: {len(down_repos)} / other: {len(repo_results)-len(up_repos)-len(down_repos)}")

    # ── 2. check API endpoints ────────────────────────────────────────────────
    api_urls = extract_api_urls(items)
    api_results = []
    if api_urls:
        print(f"\n[verifier] checking {len(api_urls)} API endpoints...")
        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(check_api_url, u) for u in api_urls]
            for fut in cf.as_completed(futs):
                api_results.append(fut.result())
        live = [r for r in api_results if r["status"] in ("UP", "UP_AUTH")]
        print(f"  Live endpoints: {len(live)}/{len(api_urls)}")

    # ── 3. check docker images ────────────────────────────────────────────────
    docker_images = extract_docker_images(items)
    docker_results = []
    if docker_images:
        print(f"\n[verifier] checking {len(docker_images)} Docker images...")
        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(check_docker_image, img) for img in docker_images]
            for fut in cf.as_completed(futs):
                docker_results.append(fut.result())
        exists = [r for r in docker_results if r["status"] == "EXISTS"]
        print(f"  Docker images found: {len(exists)}/{len(docker_images)}")

    # ── output ────────────────────────────────────────────────────────────────
    output = {
        "source": input_path,
        "repos": {
            "up": sorted(up_repos, key=lambda x: x.get("stars", 0), reverse=True),
            "down": down_repos,
        },
        "api_endpoints": {
            "live": [r for r in api_results if r["status"] in ("UP", "UP_AUTH")],
            "dead": [r for r in api_results if r["status"] not in ("UP", "UP_AUTH", "SKIPPED")],
        },
        "docker_images": {
            "exists": [r for r in docker_results if r["status"] == "EXISTS"],
            "missing": [r for r in docker_results if r["status"] != "EXISTS"],
        },
    }

    out = out_path or input_path.replace(".json", "__verified.json")
    Path(out).write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[verifier] Saved -> {out}")

    # ── print summary ─────────────────────────────────────────────────────────
    print("\n=== LIVE REPOS (top 15 by stars) ===")
    for r in output["repos"]["up"][:15]:
        print(f"  {r['status']:10} {r.get('stars',0):>6}* {r['repo']}")

    if output["api_endpoints"]["live"]:
        print("\n=== LIVE API ENDPOINTS ===")
        for r in output["api_endpoints"]["live"][:10]:
            print(f"  {r['status']:10} {r['url'][:80]}")

    if output["docker_images"]["exists"]:
        print("\n=== DOCKER IMAGES (confirmed on Hub) ===")
        for r in output["docker_images"]["exists"][:10]:
            print(f"  {r['image']}")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", required=True)
    p.add_argument("--workers", type=int, default=MAX_WORKERS)
    p.add_argument("--out", help="output JSON path")
    args = p.parse_args()
    run(args.input, args.workers, args.out)


if __name__ == "__main__":
    main()
