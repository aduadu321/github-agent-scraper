#!/usr/bin/env python3
"""End-to-end orchestrator: scraper -> merge -> downloader, per category.

CLI:
  python run_all.py                       # all categories, scrape + download
  python run_all.py --category NAME       # single category
  python run_all.py --scrape-only         # skip download phase
  python run_all.py --download-only       # skip scrape, use existing output JSON
  python run_all.py --dry-run             # print plan, no API calls
"""
from __future__ import annotations

import argparse
import glob
import json
import logging
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parent
CONFIG_DIR = ROOT / "config"
OUTPUT_DIR = ROOT / "output"
DOWNLOADS_DIR = ROOT / "downloads"
LOGS_DIR = ROOT / "logs"
LOG_FILE = LOGS_DIR / "run_all.log"

for d in (OUTPUT_DIR, DOWNLOADS_DIR, LOGS_DIR):
    d.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------- #
# logging
# --------------------------------------------------------------------------- #
def _setup_logging() -> logging.Logger:
    logger = logging.getLogger("run_all")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(fh)
    logger.addHandler(sh)
    return logger


log = _setup_logging()


# --------------------------------------------------------------------------- #
# config loading
# --------------------------------------------------------------------------- #
def load_queries() -> dict[str, list[dict[str, Any]]]:
    yaml_path = CONFIG_DIR / "queries.yaml"
    json_path = CONFIG_DIR / "queries.json"
    if yaml_path.exists():
        try:
            import yaml  # type: ignore
        except ImportError:
            yaml = None  # type: ignore
        if yaml is not None:
            with yaml_path.open(encoding="utf-8") as f:
                data = yaml.safe_load(f)
            return data["categories"]
    if json_path.exists():
        with json_path.open(encoding="utf-8") as f:
            data = json.load(f)
        return data["categories"]
    raise FileNotFoundError(f"No queries file found at {yaml_path} or {json_path}")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
_slug_re = re.compile(r"[^a-z0-9]+")


def slugify(s: str) -> str:
    s = s.lower()
    s = _slug_re.sub("_", s)
    return s.strip("_")[:80] or "query"


def output_path(category: str, query: str) -> Path:
    return OUTPUT_DIR / f"{category}__{slugify(query)}.json"


def merged_path(category: str) -> Path:
    return OUTPUT_DIR / f"{category}__MERGED.json"


# --------------------------------------------------------------------------- #
# rate-limit gate
# --------------------------------------------------------------------------- #
def wait_for_budget(min_search: int = 5, min_core: int = 50) -> None:
    try:
        import requests  # type: ignore
    except ImportError:
        log.warning("requests not installed; skipping rate-limit check")
        return
    token = os.environ.get("GITHUB_TOKEN")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = requests.get("https://api.github.com/rate_limit", headers=headers, timeout=15)
        r.raise_for_status()
        rl = r.json()["resources"]
    except Exception as e:
        log.warning("rate_limit check failed: %s", e)
        return
    s_rem = rl["search"]["remaining"]
    s_reset = rl["search"]["reset"]
    c_rem = rl["core"]["remaining"]
    c_reset = rl["core"]["reset"]
    log.info("rate_limit: search=%s core=%s", s_rem, c_rem)
    now = int(time.time())
    sleep_for = 0
    if s_rem < min_search:
        sleep_for = max(sleep_for, s_reset - now + 2)
    if c_rem < min_core:
        sleep_for = max(sleep_for, c_reset - now + 2)
    if sleep_for > 0:
        log.warning("budget low; sleeping %ss until reset", sleep_for)
        time.sleep(min(sleep_for, 3600))


# --------------------------------------------------------------------------- #
# scrape phase
# --------------------------------------------------------------------------- #
def _import_scraper():
    sys.path.insert(0, str(ROOT))
    import scraper  # type: ignore
    return scraper


def scrape_category(category: str, queries: list[dict[str, Any]],
                    dry_run: bool) -> tuple[int, int]:
    """Returns (n_queries_run, n_errors)."""
    n_err = 0
    if not dry_run:
        try:
            scraper = _import_scraper()
        except Exception as e:
            log.error("[%s] cannot import scraper.py: %s", category, e)
            return 0, len(queries)

    for qi, entry in enumerate(queries, 1):
        q = entry["q"]
        kind = entry.get("kind", "repos")
        mx = entry.get("max", 30)
        quals = entry.get("qualifiers", {}) or {}
        out = output_path(category, q)
        if dry_run:
            log.info("[%s] (%d/%d) DRY %s kind=%s max=%s quals=%s -> %s",
                     category, qi, len(queries), q, kind, mx, quals, out.name)
            continue
        try:
            results = scraper.search(q, kind=kind, max_results=mx, **quals)
            payload = {
                "category": category,
                "query": q,
                "kind": kind,
                "qualifiers": quals,
                "count": len(results) if hasattr(results, "__len__") else None,
                "results": list(results),
            }
            out.write_text(json.dumps(payload, indent=2, default=str),
                           encoding="utf-8")
            log.info("[%s] (%d/%d) %s -> %d results",
                     category, qi, len(queries), q, len(payload["results"]))
        except Exception as e:
            n_err += 1
            log.error("[%s] (%d/%d) %s FAILED: %s",
                      category, qi, len(queries), q, e)
            continue
    return len(queries), n_err


# --------------------------------------------------------------------------- #
# merge phase
# --------------------------------------------------------------------------- #
def _dedup_key(item: dict[str, Any], kind: str) -> str:
    if kind == "code":
        repo = (item.get("repo_full_name")
                or item.get("repository", {}).get("full_name")
                or item.get("full_name") or "")
        path = item.get("path") or item.get("file_path") or ""
        return f"{repo}::{path}"
    return (item.get("full_name")
            or item.get("repo_full_name")
            or item.get("name") or json.dumps(item, sort_keys=True)[:200])


def _better(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """Pick the richer record: higher stars, or later pushed_at."""
    def stars(x): return x.get("stargazers_count") or x.get("stars") or 0
    def pushed(x): return x.get("pushed_at") or x.get("updated_at") or ""
    if stars(b) > stars(a):
        return b
    if stars(b) < stars(a):
        return a
    return b if pushed(b) > pushed(a) else a


def merge_category(category: str, dry_run: bool) -> tuple[int, Path | None]:
    files = sorted(OUTPUT_DIR.glob(f"{category}__*.json"))
    files = [f for f in files if not f.name.endswith("__MERGED.json")]
    if not files:
        log.warning("[%s] merge: no per-query files found", category)
        return 0, None
    merged: dict[str, dict[str, Any]] = {}
    kind_seen = "repos"
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception as e:
            log.error("[%s] merge: cannot read %s: %s", category, f.name, e)
            continue
        kind = data.get("kind", "repos")
        kind_seen = kind
        for item in data.get("results", []):
            if not isinstance(item, dict):
                continue
            k = _dedup_key(item, kind)
            if k in merged:
                merged[k] = _better(merged[k], item)
            else:
                merged[k] = item
    out = merged_path(category)
    payload = {
        "category": category,
        "kind": kind_seen,
        "source_files": [f.name for f in files],
        "count": len(merged),
        "results": list(merged.values()),
    }
    if dry_run:
        log.info("[%s] DRY merge: %d files -> %s (~%d unique)",
                 category, len(files), out.name, len(merged))
    else:
        out.write_text(json.dumps(payload, indent=2, default=str),
                       encoding="utf-8")
        log.info("[%s] merged %d files -> %s (%d unique)",
                 category, len(files), out.name, len(merged))
    return len(merged), out


# --------------------------------------------------------------------------- #
# download phase
# --------------------------------------------------------------------------- #
def download_category(category: str, merged: Path | None,
                      dry_run: bool) -> tuple[int, int, int]:
    """Returns (downloaded, skipped, errors)."""
    out_dir = DOWNLOADS_DIR / category
    out_dir.mkdir(parents=True, exist_ok=True)
    if merged is None or not merged.exists():
        if not dry_run:
            log.warning("[%s] download: no merged JSON", category)
        return 0, 0, 0
    if dry_run:
        log.info("[%s] DRY download: %s -> %s", category, merged.name, out_dir)
        return 0, 0, 0

    # Prefer direct import.
    try:
        sys.path.insert(0, str(ROOT))
        import downloader  # type: ignore
        if hasattr(downloader, "run"):
            res = downloader.run(from_path=str(merged),
                                 category=category,
                                 out_dir=str(out_dir))
            if isinstance(res, dict):
                return (int(res.get("downloaded", 0)),
                        int(res.get("skipped", 0)),
                        int(res.get("errors", 0)))
            return 0, 0, 0
    except ImportError:
        pass
    except Exception as e:
        log.error("[%s] downloader.run failed: %s — falling back to CLI",
                  category, e)

    # CLI fallback.
    cli = [sys.executable, str(ROOT / "downloader.py"),
           "--from", str(merged),
           "--category", category,
           "--out", str(out_dir)]
    log.info("[%s] downloader CLI: %s", category, " ".join(cli))
    try:
        cp = subprocess.run(cli, check=False, capture_output=True, text=True)
        if cp.stdout:
            log.info("[%s] downloader stdout: %s", category, cp.stdout.strip())
        if cp.stderr:
            log.warning("[%s] downloader stderr: %s", category, cp.stderr.strip())
        if cp.returncode != 0:
            return 0, 0, 1
    except FileNotFoundError:
        log.error("[%s] downloader.py not found", category)
        return 0, 0, 1
    return 0, 0, 0


# --------------------------------------------------------------------------- #
# orchestration
# --------------------------------------------------------------------------- #
def run(only_category: str | None, scrape_only: bool, download_only: bool,
        dry_run: bool) -> int:
    cats = load_queries()
    if only_category:
        if only_category not in cats:
            log.error("unknown category %r (have %s)", only_category, list(cats))
            return 2
        cats = {only_category: cats[only_category]}

    log.info("plan: %d categor%s, %d queries total, dry_run=%s scrape_only=%s download_only=%s",
             len(cats), "y" if len(cats) == 1 else "ies",
             sum(len(v) for v in cats.values()),
             dry_run, scrape_only, download_only)

    overall_rc = 0
    for category, queries in cats.items():
        log.info("=== category: %s (%d queries) ===", category, len(queries))
        if not dry_run and not download_only:
            wait_for_budget()

        n_q, n_err = 0, 0
        if not download_only:
            n_q, n_err = scrape_category(category, queries, dry_run)
        unique, merged = merge_category(category, dry_run)
        dl, sk, derr = 0, 0, 0
        if not scrape_only:
            dl, sk, derr = download_category(category, merged, dry_run)

        log.info("[%s] %d queries, %d unique results, %d files downloaded, "
                 "%d skipped, %d errors",
                 category, n_q or len(queries), unique, dl, sk, n_err + derr)
    return overall_rc


# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--category", help="single category from queries.yaml")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--scrape-only", action="store_true")
    g.add_argument("--download-only", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)
    return run(only_category=args.category,
               scrape_only=args.scrape_only,
               download_only=args.download_only,
               dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
