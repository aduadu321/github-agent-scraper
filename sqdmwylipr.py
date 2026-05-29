#!/usr/bin/env python3
"""
Dedicated crypto/Web3 secret hunt.
Runs all crypto dorks from patterns.py + extra hardcoded ones.
Outputs to output/hunt_crypto.json and prints summary.
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

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from scraper import search
from patterns import GITHUB_DORK_QUERIES, PATTERNS, scan_text

# ── Crypto categories ──────────────────────────────────────────────────────

CRYPTO_CATS = {
    'eth_private_key', 'mnemonic', 'btc_wif', 'xprv_key',
    'binance', 'coinbase', 'kraken', 'infura', 'alchemy',
    'web3', 'crypto', 'private_key', 'wallet',
}

EXTRA_DORKS = [
    {"q": "PRIVATE_KEY=0x filename:.env", "kind": "code", "category": "eth_private_key"},
    {"q": "wallet mnemonic 12 words filename:.env", "kind": "code", "category": "mnemonic"},
    {"q": "web3 private_key 0x filename:config.js", "kind": "code", "category": "eth_private_key"},
    {"q": "ALCHEMY_API_KEY= filename:.env", "kind": "code", "category": "alchemy"},
    {"q": "INFURA_PROJECT_ID filename:.env", "kind": "code", "category": "infura"},
]

ENV_FILE = Path(r"C:\Users\aduad\tools\llm-rotate\.env")
TOKEN = os.environ.get("GITHUB_TOKEN", "")
if not TOKEN and ENV_FILE.exists():
    for line in ENV_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("export "): line = line[7:]
        if line.startswith("GITHUB_TOKEN="):
            TOKEN = line.split("=", 1)[1].strip().strip('"').strip("'")
            break

UA = "aduadu321-crypto-hunt/1.0"


def fetch_raw(url: str, retries: int = 3) -> str | None:
    headers = {"User-Agent": UA, "Accept": "text/plain"}
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            if e.code in (404, 403, 451):
                return None
            if e.code == 429:
                time.sleep(30 * attempt)
                continue
            if attempt < retries:
                time.sleep(2 ** attempt)
        except Exception:
            if attempt < retries:
                time.sleep(2 ** attempt)
    return None


def raw_url(row: dict) -> str | None:
    full = row.get("repo_full_name", "")
    path = row.get("path", "")
    if not full or not path:
        return None
    html = row.get("html_url", "")
    branch = "main"
    if "/blob/" in html:
        try:
            branch = html.split("/blob/", 1)[1].split("/")[0]
        except IndexError:
            pass
    owner, _, repo = full.partition("/")
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"


def mask(s: str) -> str:
    if len(s) <= 16:
        return s[:4] + "..." + s[-3:]
    return s[:10] + "..." + s[-6:]


# ── Extra crypto patterns (not in patterns.py) ─────────────────────────────

EXTRA_PATTERNS = {
    "eth_private_key_hex": {
        "regex": r"(?:PRIVATE_KEY|private_key|ETH_PRIVATE_KEY)\s*[=:]\s*['\"]?0x[0-9a-fA-F]{64}['\"]?",
        "severity": "CRITICAL",
        "false_positive_hints": ["0x0000", "example", "test", "placeholder"],
    },
    "mnemonic_12words": {
        "regex": r"(?:mnemonic|MNEMONIC|seed.phrase|SEED_PHRASE)\s*[=:]\s*['\"]?(?:[a-z]+ ){11}[a-z]+['\"]?",
        "severity": "CRITICAL",
        "false_positive_hints": ["example", "test", "word1"],
    },
    "btc_wif": {
        "regex": r"(?:WIF|PRIVATE_KEY)\s*[=:]\s*['\"]?[5KL][1-9A-HJ-NP-Za-km-z]{50,51}['\"]?",
        "severity": "CRITICAL",
        "false_positive_hints": [],
    },
    "xprv_key": {
        "regex": r"xprv[1-9A-HJ-NP-Za-km-z]{107,108}",
        "severity": "CRITICAL",
        "false_positive_hints": ["xprvExample", "testnet"],
    },
    "infura_key": {
        "regex": r"(?:INFURA_PROJECT_ID|INFURA_API_KEY)\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?",
        "severity": "HIGH",
        "false_positive_hints": ["your_project_id", "xxxx"],
    },
    "alchemy_key": {
        "regex": r"(?:ALCHEMY_API_KEY|ALCHEMY_KEY)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{30,60})['\"]?",
        "severity": "HIGH",
        "false_positive_hints": ["your_api_key", "xxxx", "test"],
    },
    "binance_api": {
        "regex": r"(?:BINANCE_API_KEY|BINANCE_SECRET)\s*[=:]\s*['\"]?([a-zA-Z0-9]{60,70})['\"]?",
        "severity": "HIGH",
        "false_positive_hints": ["your_api_key", "xxxx"],
    },
    "coinbase_api": {
        "regex": r"(?:COINBASE_API_KEY|COINBASE_SECRET)\s*[=:]\s*['\"]?([a-zA-Z0-9\-]{30,60})['\"]?",
        "severity": "HIGH",
        "false_positive_hints": ["your_api_key", "xxxx"],
    },
    "kraken_api": {
        "regex": r"(?:KRAKEN_API_KEY|KRAKEN_SECRET)\s*[=:]\s*['\"]?([a-zA-Z0-9/+=]{30,100})['\"]?",
        "severity": "HIGH",
        "false_positive_hints": ["your_api_key", "xxxx"],
    },
}


def scan_crypto(content: str, filename: str = "") -> list[dict]:
    """Scan with both patterns.py scan_text + extra crypto patterns."""
    hits = []
    try:
        hits.extend(scan_text(content, filename=filename))
    except Exception:
        pass
    lines = content.splitlines()
    for name, pat in EXTRA_PATTERNS.items():
        compiled = re.compile(pat["regex"], re.IGNORECASE)
        for lineno, line in enumerate(lines, 1):
            for m in compiled.finditer(line):
                matched = m.group(0)
                fp = any(h.lower() in matched.lower() for h in pat.get("false_positive_hints", []) if h)
                hits.append({
                    "pattern_name": name,
                    "severity": pat["severity"],
                    "matched_text": matched,
                    "line_no": lineno,
                    "is_fp_hint": fp,
                    "source": "extra_crypto",
                })
    return hits


def main():
    # Build dork list: existing crypto + extra
    dorks = [d for d in GITHUB_DORK_QUERIES if d.get("category", "").lower() in CRYPTO_CATS]
    # Add extras, skip duplicates
    existing_qs = {d["q"] for d in dorks}
    for d in EXTRA_DORKS:
        if d["q"] not in existing_qs:
            dorks.append(d)
            existing_qs.add(d["q"])

    print(f"Crypto dorks loaded: {len(dorks)}")
    print(f"GitHub token: {'YES' if TOKEN else 'NO'}")
    print()

    findings = []
    files_fetched = 0
    seen_urls: set[str] = set()

    for idx, dork in enumerate(dorks, 1):
        q = dork["q"]
        cat = dork.get("category", "?")
        kind = dork.get("kind", "code")
        print(f"  [{idx:02d}/{len(dorks)}] {cat:<20} {q}")

        try:
            rows = search(q, kind=kind, max_results=20)
        except Exception as e:
            print(f"    WARN: search error: {e}")
            continue

        print(f"    -> {len(rows)} results")

        for row in rows:
            rurl = raw_url(row)
            if not rurl or rurl in seen_urls:
                continue
            seen_urls.add(rurl)

            content = fetch_raw(rurl)
            if not content:
                continue
            files_fetched += 1
            time.sleep(0.4)

            hits = scan_crypto(content, filename=Path(row.get("path", "")).name)
            for hit in hits:
                sev = hit.get("severity", "MEDIUM")
                if sev not in ("CRITICAL", "HIGH"):
                    continue
                if hit.get("is_fp_hint"):
                    continue
                matched = hit.get("matched_text", "")
                finding = {
                    "query": q,
                    "category": cat,
                    "repo": row.get("repo_full_name", ""),
                    "path": row.get("path", ""),
                    "html_url": row.get("html_url", ""),
                    "raw_url": rurl,
                    "pattern_name": hit.get("pattern_name", ""),
                    "severity": sev,
                    "matched_masked": mask(matched),
                    "line_no": hit.get("line_no", 0),
                    "scanned_at": datetime.now(timezone.utc).isoformat(),
                }
                findings.append(finding)
                print(f"    !! {sev} [{hit.get('pattern_name','')}] {row.get('repo_full_name','')} -> {mask(matched)}")

    # ── Categorize findings ────────────────────────────────────────────────
    eth_keys = [f for f in findings if "eth_private" in f["pattern_name"] or "eth_private" in f["category"]]
    mnemonics = [f for f in findings if "mnemonic" in f["pattern_name"] or "mnemonic" in f["category"]]
    exchange = [f for f in findings if any(x in f["category"] for x in ["binance","coinbase","kraken"])]

    print()
    print("=" * 60)
    print("CRYPTO HUNT SUMMARY")
    print("=" * 60)
    print(f"Crypto dorks run     : {len(dorks)}")
    print(f"Files fetched        : {files_fetched}")
    print(f"Total findings (CRIT/HIGH, non-FP): {len(findings)}")
    print(f"ETH private keys     : {len(eth_keys)}")
    print(f"Mnemonics            : {len(mnemonics)}")
    print(f"Exchange API keys    : {len(exchange)}")
    print()

    # Save JSON
    out_path = ROOT / "output" / "hunt_crypto.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)
    print(f"Saved {len(findings)} findings -> {out_path}")

    return findings, {
        "dorks_run": len(dorks),
        "files_fetched": files_fetched,
        "eth_keys": len(eth_keys),
        "mnemonics": len(mnemonics),
        "exchange_api_keys": len(exchange),
        "total_findings": len(findings),
    }


if __name__ == "__main__":
    main()
