#!/usr/bin/env python3
"""
dedup.py — merge and deduplicate multiple hunt_secrets.py output files.

Usage:
    python dedup.py FILE1.json [FILE2.json ...] --out OUTPUT.json

Dedup key: repo + path + pattern_name
Tie-breaking:
  - Non-FP-hint preferred over FP-hint.
  - Among equal FP status, newest scanned_at wins.
"""

import argparse
import json
import sys
from pathlib import Path


def load(path: Path) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            print(f"[warn] {path}: expected list, got {type(data).__name__}", file=sys.stderr)
            return []
        return data
    except Exception as e:
        print(f"[warn] could not load {path}: {e}", file=sys.stderr)
        return []


def dedup_key(finding: dict) -> tuple:
    return (
        finding.get("repo", ""),
        finding.get("path", ""),
        finding.get("pattern_name", ""),
    )


def better(candidate: dict, incumbent: dict) -> bool:
    """Return True if candidate should replace incumbent."""
    cand_fp = bool(candidate.get("is_fp_hint", False))
    inc_fp = bool(incumbent.get("is_fp_hint", False))

    # Non-FP beats FP
    if not cand_fp and inc_fp:
        return True
    if cand_fp and not inc_fp:
        return False

    # Equal FP status — newer scanned_at wins
    cand_ts = str(candidate.get("scanned_at", ""))
    inc_ts = str(incumbent.get("scanned_at", ""))
    return cand_ts > inc_ts


def merge(files: list[Path]) -> list[dict]:
    seen: dict[tuple, dict] = {}
    total_loaded = 0
    for f in files:
        rows = load(f)
        total_loaded += len(rows)
        for row in rows:
            key = dedup_key(row)
            if key not in seen or better(row, seen[key]):
                seen[key] = row
    print(
        f"[dedup] loaded {total_loaded} rows from {len(files)} file(s) "
        f"→ {len(seen)} unique after dedup"
    )
    return list(seen.values())


def parse_args():
    p = argparse.ArgumentParser(description="Merge and deduplicate secrets JSON files")
    p.add_argument("inputs", nargs="+", help="Input JSON files")
    p.add_argument("--out", required=True, help="Output merged JSON file")
    return p.parse_args()


def main():
    args = parse_args()
    files = [Path(f) for f in args.inputs]
    missing = [f for f in files if not f.exists()]
    if missing:
        for m in missing:
            print(f"[error] file not found: {m}", file=sys.stderr)
        sys.exit(1)

    merged = merge(files)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[dedup] wrote {len(merged)} rows → {out}")


if __name__ == "__main__":
    main()
