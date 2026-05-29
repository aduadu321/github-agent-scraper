#!/usr/bin/env python3
"""
GitHub Secret Watcher — periodic monitoring daemon.

Re-runs hunt_secrets.py on a schedule, diffs against previously-seen findings,
and alerts on new ones.

CLI:
    python watcher.py [--interval 3600] [--category all|openai|aws|...]
                      [--alert-severity CRITICAL|HIGH] [--once]
                      [--state-file output\\watcher_state.json]

    python watcher.py --install-task --interval 3600
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import subprocess
import sys
import time
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

DEFAULT_STATE_FILE = OUTPUT_DIR / "watcher_state.json"
ALERT_LOG = LOG_DIR / "watcher_alerts.log"
HUNT_SCRIPT = ROOT / "hunt_secrets.py"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("watcher")
if not logger.handlers:
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler(LOG_DIR / "watcher.log", encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s\t%(levelname)s\t%(message)s"))
    logger.addHandler(fh)
    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(sh)

# ---------------------------------------------------------------------------
# ANSI colors
# ---------------------------------------------------------------------------

USE_COLOR = sys.stdout.isatty()

_COLORS = {
    "CRITICAL": "\033[1;31m",
    "HIGH":     "\033[1;33m",
    "MEDIUM":   "\033[1;34m",
    "RESET":    "\033[0m",
    "DIM":      "\033[2m",
    "CYAN":     "\033[36m",
    "GREEN":    "\033[32m",
    "BOLD":     "\033[1m",
}


def _c(key: str, text: str) -> str:
    if not USE_COLOR:
        return text
    return f"{_COLORS.get(key, '')}{text}{_COLORS['RESET']}"


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEV_ORDER: dict[str, int] = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "INFO": 0}


def _sev_ge(sev: str, threshold: str) -> bool:
    if threshold.upper() == "ALL":
        return True
    return _SEV_ORDER.get(sev.upper(), 0) >= _SEV_ORDER.get(threshold.upper(), 0)


# ---------------------------------------------------------------------------
# Finding ID
# ---------------------------------------------------------------------------

def finding_id(finding: dict) -> str:
    """sha256(repo::path::pattern_name)[:16]"""
    repo = finding.get("repo", "")
    path = finding.get("path", "")
    pattern_name = finding.get("pattern_name", "")
    raw = f"{repo}::{path}::{pattern_name}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# State file I/O
# ---------------------------------------------------------------------------

def _load_state(state_path: Path) -> dict:
    if state_path.exists():
        try:
            data = json.loads(state_path.read_text(encoding="utf-8"))
            # Normalise: seen_ids must be a list (JSON) -> set in memory
            seen = data.get("seen_ids", [])
            if not isinstance(seen, list):
                seen = list(seen)
            data["seen_ids"] = seen
            return data
        except Exception as e:
            logger.warning("Could not load state file %s: %s — starting fresh", state_path, e)
    return {
        "last_run": None,
        "cycles": 0,
        "total_findings": 0,
        "total_new": 0,
        "seen_ids": [],
    }


def _save_state(state: dict, state_path: Path) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    # seen_ids kept as list for JSON serialisation
    out = dict(state)
    out["seen_ids"] = sorted(set(out["seen_ids"]))
    try:
        state_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError as e:
        logger.error("Failed to save state: %s", e)


# ---------------------------------------------------------------------------
# Token loading — supports multiple tokens for rate-limit rotation
# ---------------------------------------------------------------------------

ENV_FALLBACK = Path(r"C:\Users\aduad\tools\llm-rotate\.env")

# Module-level token pool + round-robin index
_TOKEN_POOL: list[str] = []
_TOKEN_IDX: int = 0


def _parse_env_keys(prefix: str) -> list[str]:
    """Read all keys matching prefix (exact or prefix+'_1'..'_N') from env + .env file."""
    found: list[str] = []
    env_map: dict[str, str] = {}

    # From OS environment
    for k, v in os.environ.items():
        env_map[k] = v.strip()

    # From .env file (overrides OS env)
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
                env_map[k.strip()] = v.strip().strip('"').strip("'")
        except OSError:
            pass

    # Collect: GITHUB_TOKEN, GITHUB_TOKEN_1, GITHUB_TOKEN_2, ...
    if prefix in env_map and env_map[prefix]:
        found.append(env_map[prefix])
    for i in range(1, 20):
        key = f"{prefix}_{i}"
        if key in env_map and env_map[key]:
            found.append(env_map[key])

    return found


def _build_token_pool() -> list[str]:
    tokens = _parse_env_keys("GITHUB_TOKEN")
    if not tokens:
        logger.warning("No GitHub token found — rate limit will apply")
    else:
        logger.info("Token pool: %d token(s)", len(tokens))
    return tokens


def _load_token() -> str:
    """Return the next token in round-robin order (backwards-compat)."""
    global _TOKEN_POOL, _TOKEN_IDX
    if not _TOKEN_POOL:
        _TOKEN_POOL = _build_token_pool()
    if not _TOKEN_POOL:
        return ""
    tok = _TOKEN_POOL[_TOKEN_IDX % len(_TOKEN_POOL)]
    _TOKEN_IDX = (_TOKEN_IDX + 1) % len(_TOKEN_POOL)
    return tok


def _rotate_env_with_token(env: dict) -> dict:
    """Return env copy with the next token injected as GITHUB_TOKEN."""
    tok = _load_token()
    e = env.copy()
    if tok:
        e["GITHUB_TOKEN"] = tok
    return e


# ---------------------------------------------------------------------------
# Telegram alerting (optional — requires TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID)
# ---------------------------------------------------------------------------

def _load_telegram_config() -> tuple[str, str]:
    """Return (bot_token, chat_id) or ('', '') if not configured."""
    env_map: dict[str, str] = {}
    for k, v in os.environ.items():
        env_map[k] = v.strip()
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
                env_map[k.strip()] = v.strip().strip('"').strip("'")
        except OSError:
            pass
    bot = env_map.get("TELEGRAM_BOT_TOKEN", "")
    chat = env_map.get("TELEGRAM_CHAT_ID", "")
    return bot, chat


_TG_BOT, _TG_CHAT = "", ""
_TG_CHECKED = False


def _send_telegram(text: str) -> None:
    """Send a Telegram message (no-op if not configured)."""
    global _TG_BOT, _TG_CHAT, _TG_CHECKED
    if not _TG_CHECKED:
        _TG_BOT, _TG_CHAT = _load_telegram_config()
        _TG_CHECKED = True
    if not _TG_BOT or not _TG_CHAT:
        return
    try:
        import urllib.request, urllib.parse
        url = f"https://api.telegram.org/bot{_TG_BOT}/sendMessage"
        data = urllib.parse.urlencode({"chat_id": _TG_CHAT, "text": text, "parse_mode": "HTML"}).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=10):
            pass
        logger.info("Telegram alert sent")
    except Exception as e:
        logger.warning("Telegram send failed: %s", e)


# ---------------------------------------------------------------------------
# Alert formatting + logging
# ---------------------------------------------------------------------------

def _truncate(s: str, n: int = 50) -> str:
    if not s:
        return ""
    return s if len(s) <= n else s[:n] + "..."


def _format_alert(finding: dict, ts: str) -> str:
    sev = finding.get("severity", "?")
    cat = finding.get("pattern_name", "?")
    repo = finding.get("repo", "?")
    stars = finding.get("repo_stars")
    pushed = finding.get("repo_pushed_at", "?")
    path = finding.get("path", "?")
    line_no = finding.get("line_no", "?")
    matched = finding.get("matched_text", "")
    html_url = finding.get("html_url", "")

    stars_str = f"* {stars}" if stars is not None else "* ?"
    pushed_short = pushed[:10] if pushed and len(pushed) >= 10 else pushed

    lines = [
        f"[ALERT {ts}] NEW FINDING — {sev} {cat}",
        f"  Repo:  {repo} ({stars_str}, pushed {pushed_short})",
        f"  File:  {path} line {line_no}",
        f"  Match: {_truncate(matched, 60)}",
        f"  URL:   {html_url}",
    ]
    return "\n".join(lines)


def _emit_alert(finding: dict, ts: str) -> None:
    """Print alert to stdout and append to alert log."""
    sev = finding.get("severity", "?")
    text = _format_alert(finding, ts)

    # Colorised stdout
    color_header = _c(sev, f"[ALERT {ts}] NEW FINDING — {sev} {finding.get('pattern_name','?')}")
    color_lines = text.split("\n")
    color_lines[0] = color_header
    print("\n".join(color_lines))

    # Plain text to log file
    try:
        with ALERT_LOG.open("a", encoding="utf-8") as f:
            f.write(text + "\n" + ("-" * 72) + "\n")
    except OSError as e:
        logger.warning("Could not write to alert log: %s", e)


# ---------------------------------------------------------------------------
# Run hunt_secrets.py as subprocess
# ---------------------------------------------------------------------------

def _run_hunt(category: str, severity: str, out_json: Path) -> list[dict]:
    """
    Run hunt_secrets.py; return list of findings loaded from the output JSON.
    Falls back to loading existing output/*.json files if hunt_secrets.py
    is not available.
    """
    if not HUNT_SCRIPT.exists():
        logger.warning("hunt_secrets.py not found — using fallback mode")
        return _fallback_load_findings()

    # max-per-query=10 for targeted categories, 5 for "all" (avoids 30min timeout)
    mpq = "5" if category == "all" else "10"
    cmd = [
        sys.executable,
        str(HUNT_SCRIPT),
        "--category", category,
        "--max-per-query", mpq,
        "--severity", severity,
        "--out", str(out_json.with_suffix("")),  # hunt_secrets strips .json itself
    ]

    env = _rotate_env_with_token(os.environ.copy())

    logger.info("Running hunt: %s", " ".join(cmd))
    print(f"\n{_c('CYAN', 'Running hunt_secrets.py')} — category={category}, severity>={severity}")

    try:
        result = subprocess.run(
            cmd,
            env=env,
            capture_output=False,   # let output stream to terminal
            timeout=3600,           # 60 min max (rotation categories are smaller)
        )
        if result.returncode != 0:
            logger.warning("hunt_secrets.py exited %d", result.returncode)
    except subprocess.TimeoutExpired:
        logger.error("hunt_secrets.py timed out after 30 min")
        return []
    except Exception as e:
        logger.error("Failed to launch hunt_secrets.py: %s", e)
        return _fallback_load_findings()

    # Load the output JSON written by hunt_secrets
    # hunt_secrets appends .json to whatever prefix we give
    json_path = out_json if out_json.suffix == ".json" else out_json.with_suffix(".json")
    if not json_path.exists():
        logger.warning("Expected output %s not found after hunt run", json_path)
        return []

    try:
        findings = json.loads(json_path.read_text(encoding="utf-8"))
        if not isinstance(findings, list):
            logger.warning("Unexpected JSON format in %s", json_path)
            return []
        logger.info("Loaded %d findings from %s", len(findings), json_path)
        return findings
    except Exception as e:
        logger.error("Could not parse findings JSON %s: %s", json_path, e)
        return []


def _fallback_load_findings() -> list[dict]:
    """
    Fallback when hunt_secrets.py is missing: load any existing
    output/secrets_*.json or output/_test_findings.json.
    """
    candidates: list[Path] = sorted(OUTPUT_DIR.glob("secrets_*.json"), reverse=True)
    # Also check _test_findings.json
    test_file = OUTPUT_DIR / "_test_findings.json"
    if test_file.exists():
        candidates.append(test_file)

    if not candidates:
        logger.warning("Fallback: no findings files found in %s", OUTPUT_DIR)
        print(f"{_c('HIGH','[WARN]')} No secrets_*.json or _test_findings.json found — returning empty list")
        return []

    # Use most recent (or _test_findings.json if only that exists)
    chosen = candidates[0]
    print(f"{_c('DIM','[fallback]')} Loading findings from {chosen}")
    logger.info("Fallback: loading %s", chosen)

    try:
        data = json.loads(chosen.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
        logger.warning("Fallback file %s is not a list", chosen)
        return []
    except Exception as e:
        logger.error("Fallback load failed for %s: %s", chosen, e)
        return []


# ---------------------------------------------------------------------------
# One scan cycle
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Multi-source rotation: alternates between GitHub hunt categories + extra sources
# ---------------------------------------------------------------------------

HUNT_ROTATION = [
    # (cycle_mod, category_or_script, label)
    # category: comma-sep = multi-category | "multi_source" | "extended" | "all"
    (0,  "openai,anthropic,groq,huggingface,together,mistral,cohere,perplexity,xai,elevenlabs,replicate",
         "GitHub code — AI API Keys"),
    (1,  "aws,azure,google,firebase,cloudflare,digitalocean,hetzner,linode,vultr,railway,render,fly,vercel",
         "GitHub code — Cloud/Infrastructure Keys"),
    (2,  "github,github_oauth,gitlab,ssh,ssh_rsa,ssh_openssh,ssl_private,vault,kubernetes,npm,pypi,pulumi",
         "GitHub code — GitHub/SSH/CI Keys"),
    (3,  "eth_private_key,mnemonic,solana,xprv_key,binance,kraken,bybit,coinbase,kucoin,okx,moralis,infura,alchemy",
         "GitHub code — Crypto/Blockchain Keys"),
    (4,  "multi_source",  "Gists + Commits + HuggingFace + DockerHub"),
    (5,  "hunt_captcha",  "GitHub code — CAPTCHA solvers"),
    (6,  "hunt_vps",      "GitHub code — VPS/SSH/WireGuard"),
    (7,  "extended",      "Sourcegraph + Pastebin + npm + PyPI + Ahmia/Tor"),
    (8,  "all",           "GitHub code — ALL categories (mpq=5)"),
    (9,  "hunt_gmail",    "GitHub code — Gmail/SendGrid/SMTP"),
    (10, "multi_source",  "Gists + Commits + HuggingFace + DockerHub"),
    (11, "openai,anthropic,groq,huggingface,together,mistral,cohere,perplexity,xai,elevenlabs,replicate",
         "GitHub code — AI API Keys (repeat)"),
]
MULTI_SOURCE_SCRIPT  = Path(__file__).resolve().parent / "_multi_source_hunt.py"
EXTENDED_HUNT_SCRIPT = Path(__file__).resolve().parent / "_extended_hunt.py"


def _run_multi_source(out_json: Path) -> list[dict]:
    """Run _multi_source_hunt.py and return findings."""
    if not MULTI_SOURCE_SCRIPT.exists():
        logger.warning("_multi_source_hunt.py not found")
        return []
    env = _rotate_env_with_token(os.environ.copy())
    try:
        subprocess.run([sys.executable, str(MULTI_SOURCE_SCRIPT)], env=env, timeout=1200)
        alt_json = Path(__file__).resolve().parent / "output" / "hunt_multi_source.json"
        if alt_json.exists():
            data = json.loads(alt_json.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
    except Exception as e:
        logger.error("multi_source hunt failed: %s", e)
    return []


def _run_extended(out_json: Path) -> list[dict]:
    """Run _extended_hunt.py (Sourcegraph + Pastebin + npm + PyPI + Ahmia)."""
    if not EXTENDED_HUNT_SCRIPT.exists():
        logger.warning("_extended_hunt.py not found")
        return []
    env = _rotate_env_with_token(os.environ.copy())
    try:
        subprocess.run([sys.executable, str(EXTENDED_HUNT_SCRIPT)], env=env, timeout=1800)
        alt_json = Path(__file__).resolve().parent / "output" / "hunt_extended.json"
        if alt_json.exists():
            data = json.loads(alt_json.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
    except Exception as e:
        logger.error("extended hunt failed: %s", e)
    return []


def _run_cycle(
    state: dict,
    category: str,
    alert_severity: str,
    state_path: Path,
) -> tuple[int, int]:
    """
    Run one full scan cycle — rotates between GitHub hunt categories and
    alternative sources (Gists, Commits, HuggingFace, DockerHub).
    Returns (total_findings_this_run, new_findings_count).
    """
    ts_now = datetime.now(timezone.utc)
    ts_str = ts_now.strftime("%Y-%m-%dT%H:%M:%S")
    ts_file = ts_now.strftime("%Y%m%dT%H%M%SZ")

    # Pick rotation slot based on cycle count
    cycle_num = state.get("cycles", 0)
    slot = cycle_num % len(HUNT_ROTATION)
    _, rotation_category, rotation_label = HUNT_ROTATION[slot]

    # Override with explicit category arg if not "all"
    effective_category = category if category != "all" else rotation_category

    print(f"\n{_c('CYAN', f'[Rotation slot {slot}]')} {rotation_label}")
    print(f"  Effective category: {effective_category}")

    out_json = OUTPUT_DIR / f"watcher_{ts_file}.json"

    if effective_category == "multi_source":
        findings = _run_multi_source(out_json)
    elif effective_category == "extended":
        findings = _run_extended(out_json)
    else:
        findings = _run_hunt(effective_category, alert_severity, out_json)

    seen_ids: set[str] = set(state.get("seen_ids", []))
    new_findings: list[dict] = []

    for f in findings:
        fid = finding_id(f)
        if fid not in seen_ids:
            new_findings.append(f)
            seen_ids.add(fid)

    # Alert on new findings + Telegram for CRITICAL
    alert_count = 0
    tg_batch: list[str] = []
    for f in new_findings:
        sev = f.get("severity", "")
        if _sev_ge(sev, alert_severity):
            _emit_alert(f, ts_str)
            alert_count += 1
        if sev == "CRITICAL":
            pat = f.get("pattern_name", "?")
            repo = f.get("repo", "?")
            masked = f.get("matched_masked", "?")
            url = f.get("html_url", "")
            tg_batch.append(
                f"<b>[CRITICAL] {pat}</b>\nRepo: {repo}\nMatch: <code>{masked}</code>\n{url}"
            )

    # Send batched Telegram alert (max 5 per cycle to avoid flood)
    if tg_batch:
        header = f"<b>[GH-Hunter] {len(tg_batch)} CRITICAL finding(s) — cycle {state.get('cycles',0)+1}</b>"
        msg = header + "\n\n" + "\n---\n".join(tg_batch[:5])
        if len(tg_batch) > 5:
            msg += f"\n\n...and {len(tg_batch)-5} more (see alert log)"
        _send_telegram(msg)

    total = len(findings)
    new_total = len(new_findings)

    # Update state
    state["last_run"] = ts_str
    state["cycles"] = state.get("cycles", 0) + 1
    state["total_findings"] = state.get("total_findings", 0) + total
    state["total_new"] = state.get("total_new", 0) + new_total
    state["seen_ids"] = sorted(seen_ids)

    # FP tracking — record pattern_name of non-FP vs FP
    fp_stats = state.setdefault("fp_stats", {})
    for f in new_findings:
        pat = f.get("pattern_name", "unknown")
        matched = f.get("matched_masked", "") or ""
        is_fp = any(h in matched.lower() for h in
                    ["example", "test", "changeme", "xxxx", "placeholder", "dummy", "sample", "<key>"])
        key = f"{pat}::fp" if is_fp else f"{pat}::valid"
        fp_stats[key] = fp_stats.get(key, 0) + 1

    _save_state(state, state_path)

    # Auto-merge: consolidate all hunt_*.json into merged_findings.json
    try:
        _auto_merge()
    except Exception as e:
        logger.warning("Auto-merge failed: %s", e)

    # Cycle summary
    print()
    print(f"{_c('BOLD','-' * 60)}")
    print(f"{_c('CYAN','Cycle summary')} [{ts_str}]")
    print(f"  Findings this run  : {total}")
    print(f"  New (unseen)       : {new_total}")
    print(f"  Alerted (>={alert_severity}): {alert_count}")
    print(f"  Telegram CRITICAL  : {len(tg_batch)}")
    print(f"  Total cycles       : {state['cycles']}")
    print(f"  Total unique seen  : {len(seen_ids)}")
    print(f"  Token pool size    : {len(_TOKEN_POOL) or 1}")
    print(f"  State file         : {state_path}")
    print(f"  Alert log          : {ALERT_LOG}")
    print(f"{_c('BOLD','-' * 60)}")

    logger.info(
        "cycle=%d findings=%d new=%d alerted=%d crit_tg=%d seen_total=%d tokens=%d",
        state["cycles"], total, new_total, alert_count, len(tg_batch),
        len(seen_ids), len(_TOKEN_POOL) or 1,
    )

    return total, new_total


# ---------------------------------------------------------------------------
# Auto-merge: consolidate all hunt_*.json output files
# ---------------------------------------------------------------------------

def _auto_merge() -> None:
    """Merge all hunt_*.json files into a single merged_findings.json."""
    import glob as _glob
    merged: list[dict] = []
    seen_keys: set[str] = set()
    json_files = sorted(_glob.glob(str(OUTPUT_DIR / "hunt_*.json")))
    json_files += sorted(_glob.glob(str(OUTPUT_DIR / "watcher_*.json")))

    for fp in json_files:
        try:
            data = json.loads(Path(fp).read_text(encoding="utf-8"))
            if not isinstance(data, list):
                continue
            for item in data:
                k = f"{item.get('pattern_name')}::{item.get('repo')}::{item.get('matched_masked')}"
                if k not in seen_keys:
                    seen_keys.add(k)
                    merged.append(item)
        except Exception:
            pass

    if merged:
        out = OUTPUT_DIR / "merged_findings.json"
        out.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
        logger.info("Auto-merge: %d unique findings -> %s", len(merged), out)
        print(f"  [merge] {len(merged)} unique findings -> merged_findings.json")


# ---------------------------------------------------------------------------
# Task Scheduler integration
# ---------------------------------------------------------------------------

def _install_task(interval_seconds: int, script_path: Path) -> None:
    """
    Print (and attempt to run) a schtasks /create command that schedules
    watcher.py --once every `interval_seconds` seconds (rounded to minutes).
    """
    interval_min = max(1, interval_seconds // 60)
    python_exe = sys.executable
    script = str(script_path)

    # Task runs every N minutes; /sc MINUTE /mo N
    cmd_parts = [
        "schtasks", "/create",
        "/tn", "GitHubSecretWatcher",
        "/tr", f'"{python_exe}" "{script}" --once',
        "/sc", "MINUTE",
        "/mo", str(interval_min),
        "/rl", "HIGHEST",
        "/f",
    ]
    cmd_str = " ".join(cmd_parts)

    print()
    print(f"{_c('CYAN','Windows Task Scheduler integration')}")
    print(f"  Task name : GitHubSecretWatcher")
    print(f"  Schedule  : every {interval_min} minute(s)")
    print(f"  Command   : {python_exe} {script} --once")
    print()
    print(f"  Full schtasks command:")
    print(f"  {cmd_str}")
    print()

    # Attempt to actually create the task
    try:
        result = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            print(f"{_c('GREEN','SUCCESS')} Task created successfully.")
            if result.stdout.strip():
                print(f"  {result.stdout.strip()}")
        else:
            stderr = result.stderr.strip() or result.stdout.strip()
            print(f"{_c('HIGH','WARN')} schtasks returned exit {result.returncode}:")
            print(f"  {stderr}")
            print(f"  (Run the command above as Administrator if permission was denied)")
    except FileNotFoundError:
        print(f"{_c('HIGH','WARN')} schtasks.exe not found — run the command manually.")
    except Exception as e:
        print(f"{_c('HIGH','WARN')} Could not run schtasks: {e}")
        print(f"  Run the command above manually (may need Administrator).")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="GitHub Secret Watcher — periodic monitoring daemon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--interval",
        type=int,
        default=3600,
        help="Seconds between scan cycles (default: 3600, min: 300)",
    )
    p.add_argument(
        "--category",
        default="all",
        help="Hunt category: all|openai|aws|anthropic|github|huggingface (default: all)",
    )
    p.add_argument(
        "--alert-severity",
        dest="alert_severity",
        default="HIGH",
        help="Minimum severity to alert on: CRITICAL|HIGH|MEDIUM|all (default: HIGH)",
    )
    p.add_argument(
        "--once",
        action="store_true",
        help="Run one cycle then exit (useful for cron/Task Scheduler)",
    )
    p.add_argument(
        "--state-file",
        dest="state_file",
        default=str(DEFAULT_STATE_FILE),
        help=f"Path to state JSON (default: {DEFAULT_STATE_FILE})",
    )
    p.add_argument(
        "--install-task",
        action="store_true",
        dest="install_task",
        help="Create a Windows Scheduled Task (GitHubSecretWatcher) and exit",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    # ---- --install-task mode -----------------------------------------------
    if args.install_task:
        _install_task(args.interval, Path(__file__).resolve())
        return 0

    # ---- Enforce minimum interval ------------------------------------------
    interval = max(300, args.interval)
    if interval != args.interval:
        print(f"{_c('HIGH','[WARN]')} --interval raised to minimum 300s")

    state_path = Path(args.state_file)
    state = _load_state(state_path)

    print()
    print(f"{_c('BOLD','=== GitHub Secret Watcher ===')}  (PID {os.getpid()})")
    print(f"  Category       : {args.category}")
    print(f"  Alert severity : >= {args.alert_severity}")
    print(f"  Interval       : {interval}s")
    print(f"  Mode           : {'--once' if args.once else 'daemon'}")
    print(f"  State file     : {state_path}")
    print(f"  Prev cycles    : {state.get('cycles', 0)}")
    print(f"  Total seen IDs : {len(state.get('seen_ids', []))}")
    print()

    if args.once:
        _run_cycle(state, args.category, args.alert_severity, state_path)
        return 0

    # ---- Daemon loop -------------------------------------------------------
    cycle_num = 0
    while True:
        cycle_num += 1
        print(f"\n{_c('CYAN', f'=== Cycle {cycle_num} ===')}")
        try:
            _run_cycle(state, args.category, args.alert_severity, state_path)
        except KeyboardInterrupt:
            print(f"\n{_c('DIM','Interrupted — exiting.')}")
            return 0
        except Exception as e:
            logger.error("Unexpected error in cycle %d: %s", cycle_num, e, exc_info=True)
            print(f"{_c('HIGH','[ERROR]')} Cycle failed: {e} — will retry next interval")

        print(f"\n{_c('DIM', f'Sleeping {interval}s until next cycle...')}")
        try:
            time.sleep(interval)
        except KeyboardInterrupt:
            print(f"\n{_c('DIM','Interrupted — exiting.')}")
            return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
