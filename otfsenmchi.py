"""
pipeline.py — master end-to-end orchestrator for github-scraper.

Usage:
  python pipeline.py [--mode full|hunt|deploy|monitor]
                     [--category all|openai|aws|...]
                     [--dry-run]
                     [--quick]

Modes:
  full    Run all 10 steps top-to-bottom.
  hunt    Steps 1-4 + 8 + 9 (scrape, hunt, git-scan, dedup, report).
  deploy  Steps 3-7   (hunt secrets, dedup, validate, integrate, inject).
  monitor Step 10 only (watcher --once).

--quick  Skip step 1 (dork_gen) and step 8 (git_history_scan); cap max-per-query=10.
--dry-run Print the full step plan with exact commands, exit 0.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.resolve()

# ---------------------------------------------------------------------------
# Step definitions
# Each step: (step_num, script_name, base_args_fn)
# base_args_fn receives (category, quick, mode) and returns list[str]
# ---------------------------------------------------------------------------

def _step_dork_gen(category, quick, mode):
    cat = "all" if category == "all" else category
    return ["dork_gen.py", "--category", cat, "--count", "10",
            "--append-to", str(PROJECT_ROOT / "config" / "queries.yaml")]

def _step_run_all(category, quick, mode):
    args = ["run_all.py", "--scrape-only"]
    if category != "all":
        args += ["--category", category]
    return args

def _step_hunt_secrets(category, quick, mode):
    args = ["hunt_secrets.py", "--category", category if category else "all"]
    if quick:
        args += ["--max-per-query", "10"]
    else:
        args += ["--max-per-query", "30"]
    return args

def _step_dedup(category, quick, mode):
    secrets_glob = str(PROJECT_ROOT / "output" / "secrets_*.json")
    out = str(PROJECT_ROOT / "output" / "secrets_MERGED.json")
    # dedup.py takes positional glob-expanded files; we pass the glob and let
    # the subprocess shell expand it — but subprocess doesn't shell-expand on
    # Windows, so we expand here.
    files = sorted(PROJECT_ROOT.glob("output/secrets_*.json"))
    # Filter out the MERGED file itself
    files = [str(f) for f in files if "MERGED" not in f.name]
    if not files:
        # Fall back to a placeholder that will be caught at runtime
        files = [secrets_glob]
    return ["dedup.py"] + files + ["--out", out]

def _step_validator(category, quick, mode):
    inp = str(PROJECT_ROOT / "output" / "secrets_MERGED.json")
    out = str(PROJECT_ROOT / "output" / "validated_MERGED.json")
    return ["validator.py", "--input", inp, "--out", out]

def _step_api_integrator(category, quick, mode):
    inp = str(PROJECT_ROOT / "output" / "validated_MERGED.json")
    return ["api_integrator.py", "--input", inp, "--inject-llm-rotate"]

def _step_llm_inject(category, quick, mode):
    src = str(PROJECT_ROOT / "found_agents" / "found_keys.env")
    return ["llm_inject.py", "--source", src, "--test-first"]

def _step_git_history_scan(category, quick, mode):
    inp = str(PROJECT_ROOT / "output" / "rest_agents__MERGED.json")
    return ["git_history_scan.py", "--from-file", inp, "--top", "5", "--max-commits", "50"]

def _step_report(category, quick, mode):
    s = str(PROJECT_ROOT / "output" / "secrets_MERGED.json")
    v = str(PROJECT_ROOT / "output" / "validated_MERGED.json")
    out = str(PROJECT_ROOT / "output" / "report")
    return ["report.py", "--input", s, v, "--format", "all", "--exclude-fp",
            "--out", out]

def _step_watcher(category, quick, mode):
    return ["watcher.py", "--once"]


# Full ordered step list: (label, builder_fn)
ALL_STEPS = [
    ("dork_gen.py",         _step_dork_gen),
    ("run_all.py",          _step_run_all),
    ("hunt_secrets.py",     _step_hunt_secrets),
    ("dedup.py",            _step_dedup),
    ("validator.py",        _step_validator),
    ("api_integrator.py",   _step_api_integrator),
    ("llm_inject.py",       _step_llm_inject),
    ("git_history_scan.py", _step_git_history_scan),
    ("report.py",           _step_report),
    ("watcher.py",          _step_watcher),
]

# Indices (1-based) active per mode
MODE_STEPS = {
    "full":    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    "hunt":    [1, 2, 3, 4, 8, 9],
    "deploy":  [3, 4, 5, 6, 7],
    "monitor": [10],
}

# Steps skipped by --quick (1-based indices from full list)
QUICK_SKIP = {1, 8}


# ---------------------------------------------------------------------------
# Progress bar
# ---------------------------------------------------------------------------

def _progress(step_idx, total, label, width=40):
    filled = int(width * step_idx / total)
    bar = "=" * filled + ">" + " " * (width - filled - 1) if filled < width else "=" * width
    print(f"\r[{bar}] Step {step_idx}/{total} {label}", flush=True)


# ---------------------------------------------------------------------------
# Parse stdout for summary counts
# ---------------------------------------------------------------------------

def _parse_counts(stdout: str) -> dict:
    """Try to extract finding/validation/injection counts from script stdout."""
    counts = {"findings": 0, "validated": 0, "injected": 0, "agents": 0}

    for line in stdout.splitlines():
        ll = line.lower()
        # dedup / hunt: "N rows" or "N unique findings"
        for kw in ("unique findings", "findings:", "rows →", "rows ->"):
            if kw in ll:
                for tok in line.split():
                    if tok.isdigit():
                        counts["findings"] = max(counts["findings"], int(tok))
                        break

        # validator: "Summary: {'VALID': N, ...}"
        if "summary:" in ll and "valid" in ll:
            try:
                import re
                m = re.search(r"'VALID'\s*:\s*(\d+)", line)
                if m:
                    counts["validated"] = int(m.group(1))
            except Exception:
                pass

        # llm_inject: "injected N keys"
        if "injected" in ll:
            for tok in line.split():
                if tok.isdigit():
                    counts["injected"] = max(counts["injected"], int(tok))
                    break

        # api_integrator: "created N agents" or "agents created: N"
        if "agent" in ll and ("created" in ll or "generat" in ll):
            for tok in line.split():
                if tok.isdigit():
                    counts["agents"] = max(counts["agents"], int(tok))
                    break

    return counts


# ---------------------------------------------------------------------------
# Run one step
# ---------------------------------------------------------------------------

def _run_step(script_name: str, args: list[str], dry_run: bool) -> dict:
    """Execute a single pipeline step. Returns result dict."""
    script_path = PROJECT_ROOT / script_name
    cmd = [sys.executable, str(script_path)] + args[1:]  # args[0] is script_name

    result = {
        "script": script_name,
        "cmd": cmd,
        "status": "SKIPPED",
        "elapsed": 0.0,
        "stdout": "",
        "stderr": "",
        "counts": {},
    }

    if not script_path.exists():
        result["status"] = "MISSING"
        print(f"  [WARN] {script_name} not found — step skipped.")
        return result

    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        elapsed = time.monotonic() - t0
        result["elapsed"] = elapsed
        result["stdout"] = proc.stdout
        result["stderr"] = proc.stderr
        result["counts"] = _parse_counts(proc.stdout)

        if proc.returncode == 0:
            result["status"] = "OK"
        else:
            result["status"] = "FAILED"
            print(f"  [ERROR] {script_name} exited {proc.returncode}")
            if proc.stderr.strip():
                for ln in proc.stderr.strip().splitlines()[-5:]:
                    print(f"         {ln}")
    except Exception as exc:
        result["elapsed"] = time.monotonic() - t0
        result["status"] = "ERROR"
        result["stderr"] = str(exc)
        print(f"  [ERROR] {script_name} raised: {exc}")

    return result


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

def _print_summary(results: list[dict], ts: str, total_elapsed: float):
    ok_count = sum(1 for r in results if r["status"] == "OK")
    failed_count = sum(1 for r in results if r["status"] in ("FAILED", "ERROR", "MISSING"))
    skipped_count = sum(1 for r in results if r["status"] == "SKIPPED")

    # Aggregate counts across all steps
    total_findings = max((r["counts"].get("findings", 0) for r in results), default=0)
    total_validated = max((r["counts"].get("validated", 0) for r in results), default=0)
    total_injected = max((r["counts"].get("injected", 0) for r in results), default=0)
    total_agents = max((r["counts"].get("agents", 0) for r in results), default=0)

    # Also try reading output files for more accurate counts
    merged = PROJECT_ROOT / "output" / "secrets_MERGED.json"
    validated = PROJECT_ROOT / "output" / "validated_MERGED.json"
    if merged.exists():
        try:
            data = json.loads(merged.read_text(encoding="utf-8"))
            total_findings = max(total_findings, len(data))
        except Exception:
            pass
    if validated.exists():
        try:
            data = json.loads(validated.read_text(encoding="utf-8"))
            valid_keys = [d for d in data if d.get("validation_status") == "VALID"]
            total_validated = max(total_validated, len(valid_keys))
        except Exception:
            pass

    print()
    print(f"PIPELINE SUMMARY — {ts}")
    print("=" * 56)
    print(f"{'Step':<6}{'Script':<22}{'Status':<10}{'Time':>8}")
    print("-" * 56)
    for i, r in enumerate(results, 1):
        status = r["status"]
        elapsed_str = f"{r['elapsed']:.1f}s"
        print(f"{i:<6}{r['script']:<22}{status:<10}{elapsed_str:>8}")
    print("=" * 56)
    skipped_str = f" | {skipped_count} SKIPPED" if skipped_count else ""
    print(f"Total: {total_elapsed:.1f}s | {ok_count} OK | {failed_count} FAILED{skipped_str}")
    print(f"Findings: {total_findings} | Validated: {total_validated} | "
          f"Injected: {total_injected} | Agents created: {total_agents}")
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args():
    p = argparse.ArgumentParser(
        description="github-scraper master pipeline orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--mode", choices=["full", "hunt", "deploy", "monitor"], default="full",
        help="Pipeline mode (default: full)",
    )
    p.add_argument(
        "--category", default="all",
        help="Secret category filter (all|openai|aws|anthropic|...). Default: all",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Print full step plan with exact commands, exit 0.",
    )
    p.add_argument(
        "--quick", action="store_true",
        help="Skip dork_gen + git_history_scan; cap max-per-query=10.",
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = _parse_args()

    active_indices = set(MODE_STEPS[args.mode])
    if args.quick:
        active_indices -= QUICK_SKIP

    # Build the ordered list of active steps with their args
    planned = []
    for full_idx, (label, builder) in enumerate(ALL_STEPS, 1):
        if full_idx not in active_indices:
            continue
        step_args = builder(args.category, args.quick, args.mode)
        planned.append((full_idx, label, step_args))

    # --dry-run: print plan and exit
    if args.dry_run:
        print(f"PIPELINE DRY-RUN — mode={args.mode} category={args.category} "
              f"quick={args.quick}")
        print(f"Active steps: {len(planned)}")
        print("=" * 70)
        for rank, (full_idx, label, step_args) in enumerate(planned, 1):
            cmd = [sys.executable, str(PROJECT_ROOT / label)] + step_args[1:]
            cmd_str = " ".join(str(c) for c in cmd)
            print(f"Step {rank} (#{full_idx}): {label}")
            print(f"  cmd: {cmd_str}")
            print()
        print("[dry-run] No steps executed.")
        return 0

    # Live run
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    print(f"github-scraper pipeline — {ts}")
    print(f"mode={args.mode}  category={args.category}  "
          f"quick={args.quick}  steps={len(planned)}")
    print()

    results = []
    total_t0 = time.monotonic()

    for rank, (full_idx, label, step_args) in enumerate(planned, 1):
        _progress(rank, len(planned), label)
        print(f"\nSTEP {rank}/{len(planned)} [{label}]")
        print(f"  args: {' '.join(str(a) for a in step_args[1:])}")

        # For dedup: re-expand glob at runtime (files may not exist at parse time)
        if label == "dedup.py":
            files = sorted(PROJECT_ROOT.glob("output/secrets_*.json"))
            files = [str(f) for f in files if "MERGED" not in f.name]
            if files:
                step_args = ["dedup.py"] + files + [
                    "--out", str(PROJECT_ROOT / "output" / "secrets_MERGED.json")
                ]
            else:
                print("  [WARN] No secrets_*.json files found — skipping dedup.")
                results.append({
                    "script": label, "cmd": [], "status": "SKIPPED",
                    "elapsed": 0.0, "stdout": "", "stderr": "", "counts": {},
                })
                continue

        result = _run_step(label, step_args, args.dry_run)
        results.append(result)

        status_display = result["status"]
        print(f"  -> {status_display}  ({result['elapsed']:.1f}s)")

        # Print last few lines of stdout for context
        if result["stdout"].strip():
            lines = result["stdout"].strip().splitlines()
            for ln in lines[-4:]:
                if ln.strip():
                    print(f"     {ln}")

    total_elapsed = time.monotonic() - total_t0
    _print_summary(results, ts, total_elapsed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
