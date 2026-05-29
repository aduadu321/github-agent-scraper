"""
validator.py — validate liveness of API keys found by hunt_secrets.py.

CLI:
  python validator.py --input output/secrets_TIMESTAMP.json
                      [--out output/validated_TIMESTAMP.json]
                      [--dry-run]
                      [--timeout 8]

Status values: VALID / INVALID / RATE_LIMITED / ERROR / UNKNOWN / SKIPPED_FP
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------

ENV_FILE = r"C:\Users\aduad\tools\llm-rotate\.env"


def _load_env_file(path: str) -> dict:
    """Parse a .env file and return key→value mapping."""
    result = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, _, v = line.partition("=")
                    result[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return result


def _github_token() -> str:
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        env = _load_env_file(ENV_FILE)
        token = env.get("GITHUB_TOKEN", "")
    return token


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------


def _request(method: str, url: str, headers: dict, body: bytes | None,
             timeout: int) -> tuple[int, bytes]:
    """
    Make one HTTP request.  Returns (status_code, response_body_bytes).
    Never raises — always returns (0, b"") on network error.
    """
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        body_bytes = b""
        try:
            body_bytes = exc.read()
        except Exception:
            pass
        return exc.code, body_bytes
    except Exception as exc:
        return 0, str(exc).encode()


# ---------------------------------------------------------------------------
# Validation methods — one per pattern_name
# ---------------------------------------------------------------------------


def _validate_openai(key: str, timeout: int) -> tuple[str, int, str]:
    code, body = _request(
        "GET",
        "https://api.openai.com/v1/models",
        {"Authorization": f"Bearer {key}", "User-Agent": "validator/1.0"},
        None,
        timeout,
    )
    if code == 200:
        return "VALID", code, ""
    if code == 401:
        return "INVALID", code, ""
    if code == 429:
        return "RATE_LIMITED", code, ""
    return "ERROR", code, body[:200].decode(errors="replace")


def _validate_anthropic(key: str, timeout: int) -> tuple[str, int, str]:
    payload = json.dumps({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 1,
        "messages": [{"role": "user", "content": "hi"}],
    }).encode()
    code, body = _request(
        "POST",
        "https://api.anthropic.com/v1/messages",
        {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
            "User-Agent": "validator/1.0",
        },
        payload,
        timeout,
    )
    if code == 200:
        return "VALID", code, ""
    if code in (401, 403):
        return "INVALID", code, ""
    if code == 429:
        return "RATE_LIMITED", code, ""
    return "ERROR", code, body[:200].decode(errors="replace")


def _validate_github_pat(key: str, timeout: int) -> tuple[str, int, str]:
    code, body = _request(
        "GET",
        "https://api.github.com/user",
        {
            "Authorization": f"Bearer {key}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "validator/1.0",
        },
        None,
        timeout,
    )
    if code == 200:
        return "VALID", code, ""
    if code == 401:
        return "INVALID", code, ""
    if code == 429:
        return "RATE_LIMITED", code, ""
    return "ERROR", code, body[:200].decode(errors="replace")


def _validate_aws_key(matched_text: str, timeout: int) -> tuple[str, int, str]:
    # AWS validation requires both access key ID (AKIA...) and secret.
    # We can't safely sign a request without the secret, so mark UNKNOWN.
    return "UNKNOWN", 0, "AWS validation requires secret key — cannot validate AKIA alone"


def _validate_huggingface(key: str, timeout: int) -> tuple[str, int, str]:
    code, body = _request(
        "GET",
        "https://huggingface.co/api/whoami",
        {"Authorization": f"Bearer {key}", "User-Agent": "validator/1.0"},
        None,
        timeout,
    )
    if code == 200:
        return "VALID", code, ""
    if code == 401:
        return "INVALID", code, ""
    if code == 429:
        return "RATE_LIMITED", code, ""
    return "ERROR", code, body[:200].decode(errors="replace")


def _validate_groq(key: str, timeout: int) -> tuple[str, int, str]:
    code, body = _request(
        "GET",
        "https://api.groq.com/openai/v1/models",
        {"Authorization": f"Bearer {key}", "User-Agent": "validator/1.0"},
        None,
        timeout,
    )
    if code == 200:
        return "VALID", code, ""
    if code == 401:
        return "INVALID", code, ""
    if code == 429:
        return "RATE_LIMITED", code, ""
    return "ERROR", code, body[:200].decode(errors="replace")


def _validate_google_api(key: str, timeout: int) -> tuple[str, int, str]:
    # AIza... keys are API keys, not OAuth tokens; tokeninfo endpoint is for
    # OAuth access tokens.  We do a heuristic: check if key starts with "AIza"
    # and has correct length (39 chars).  Cannot truly validate without a
    # specific API scoped call that may have side effects.
    if key.startswith("AIza") and len(key) == 39:
        return "UNKNOWN", 0, "Google API key heuristic: correct format, live check skipped"
    return "UNKNOWN", 0, "Google API key: format mismatch"


def _validate_stripe(key: str, timeout: int) -> tuple[str, int, str]:
    code, body = _request(
        "GET",
        "https://api.stripe.com/v1/account",
        {"Authorization": f"Bearer {key}", "User-Agent": "validator/1.0"},
        None,
        timeout,
    )
    if code == 200:
        return "VALID", code, ""
    if code == 401:
        return "INVALID", code, ""
    if code == 429:
        return "RATE_LIMITED", code, ""
    return "ERROR", code, body[:200].decode(errors="replace")


def _validate_slack(key: str, timeout: int) -> tuple[str, int, str]:
    code, body = _request(
        "GET",
        "https://slack.com/api/auth.test",
        {"Authorization": f"Bearer {key}", "User-Agent": "validator/1.0"},
        None,
        timeout,
    )
    if code == 200:
        try:
            data = json.loads(body)
            if data.get("ok"):
                return "VALID", code, ""
            return "INVALID", code, data.get("error", "")
        except Exception:
            return "ERROR", code, "JSON parse error"
    if code == 401:
        return "INVALID", code, ""
    if code == 429:
        return "RATE_LIMITED", code, ""
    return "ERROR", code, body[:200].decode(errors="replace")


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

VALIDATORS = {
    "openai":      _validate_openai,
    "anthropic":   _validate_anthropic,
    "github_pat":  _validate_github_pat,
    "aws_key":     _validate_aws_key,
    "huggingface": _validate_huggingface,
    "groq":        _validate_groq,
    "google_api":  _validate_google_api,
    "stripe":      _validate_stripe,
    "slack":       _validate_slack,
}

# Aliases: hunt_secrets.py may use longer names like "openai_api_key".
# Map them to the canonical short names above.
_PATTERN_ALIASES: dict[str, str] = {
    "openai_api_key":      "openai",
    "openai_key":          "openai",
    "anthropic_api_key":   "anthropic",
    "anthropic_key":       "anthropic",
    "github_token":        "github_pat",
    "github_pat_token":    "github_pat",
    "aws_access_key":      "aws_key",
    "aws_secret_key":      "aws_key",
    "aws_key_id":          "aws_key",
    "huggingface_token":   "huggingface",
    "hf_token":            "huggingface",
    "groq_api_key":        "groq",
    "groq_key":            "groq",
    "google_api_key":      "google_api",
    "stripe_key":          "stripe",
    "stripe_api_key":      "stripe",
    "stripe_secret":       "stripe",
    "slack_token":         "slack",
    "slack_bot_token":     "slack",
}


def _canonical_pattern(pattern_name: str) -> str:
    """Return canonical short name, or the original if no alias found."""
    low = pattern_name.lower()
    return _PATTERN_ALIASES.get(low, low)


# ---------------------------------------------------------------------------
# Core validator
# ---------------------------------------------------------------------------


def _truncate_key(key: str, n: int = 6) -> str:
    """Show first n and last 3 chars for log display."""
    if len(key) <= n + 3:
        return key[:n] + "..."
    return key[:n] + "..." + key[-3:]


def validate_finding(finding: dict, timeout: int, dry_run: bool) -> dict:
    """
    Enrich one finding with validation_status, validated_at,
    validation_http_code, validation_note.
    """
    out = dict(finding)
    now_iso = datetime.now(timezone.utc).isoformat()

    raw_pattern = finding.get("pattern_name", "")
    pattern = _canonical_pattern(raw_pattern)   # normalize aliases
    key = finding.get("matched_text", "").strip()
    repo = finding.get("repo", "")
    path = finding.get("path", "")

    # Store resolved canonical pattern for transparency
    if pattern != raw_pattern.lower():
        out["pattern_name_resolved"] = pattern

    # --- FP hint skip ---
    if finding.get("is_fp_hint"):
        out["validation_status"] = "SKIPPED_FP"
        out["validated_at"] = now_iso
        out["validation_http_code"] = None
        out["validation_note"] = "is_fp_hint=true — skipped"
        print(f"[SKIPPED_FP] {raw_pattern} {repo} {path}")
        return out

    # --- Dry-run ---
    if dry_run:
        has_validator = pattern in VALIDATORS
        action = f"would call {pattern} validator" if has_validator else f"UNKNOWN (no validator for '{pattern}')"
        out["validation_status"] = "DRY_RUN"
        out["validated_at"] = now_iso
        out["validation_http_code"] = None
        out["validation_note"] = action
        print(f"[DRY_RUN] {raw_pattern} -> {pattern} | {repo} {path} — {_truncate_key(key)}")
        return out

    # --- No validator ---
    if pattern not in VALIDATORS:
        out["validation_status"] = "UNKNOWN"
        out["validated_at"] = now_iso
        out["validation_http_code"] = None
        out["validation_note"] = f"No validator for pattern '{pattern}'"
        print(f"[UNKNOWN]   {raw_pattern} {repo} {path}")
        return out

    # --- AWS special case: needs matched_text but also checks for secret ---
    if pattern == "aws_key":
        status, http_code, note = _validate_aws_key(key, timeout)
        out["validation_status"] = status
        out["validated_at"] = now_iso
        out["validation_http_code"] = http_code or None
        out["validation_note"] = note
        print(f"[{status:<12}] {raw_pattern} {repo} {path} {_truncate_key(key)}")
        return out

    # --- All other validators ---
    try:
        status, http_code, note = VALIDATORS[pattern](key, timeout)
    except Exception as exc:
        status, http_code, note = "ERROR", 0, str(exc)[:200]

    out["validation_status"] = status
    out["validated_at"] = now_iso
    out["validation_http_code"] = http_code if http_code else None
    out["validation_note"] = note

    marker = f"[{status}]"
    print(f"{marker:<14} {raw_pattern} {repo} {path} {_truncate_key(key)}")
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _default_out(input_path: str) -> str:
    stem = os.path.splitext(os.path.basename(input_path))[0]
    stem = stem.replace("secrets_", "validated_")
    if not stem.startswith("validated_"):
        stem = "validated_" + stem
    return os.path.join(os.path.dirname(input_path), stem + ".json")


def main():
    parser = argparse.ArgumentParser(
        description="Validate liveness of API keys found by hunt_secrets.py."
    )
    parser.add_argument("--input", required=True, help="Input findings JSON")
    parser.add_argument("--out", help="Output validated JSON (default: auto-named)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be validated; no API calls")
    parser.add_argument("--timeout", type=int, default=8,
                        help="Per-call timeout in seconds (default: 8)")
    args = parser.parse_args()

    # Load input
    try:
        with open(args.input, encoding="utf-8") as fh:
            findings = json.load(fh)
    except FileNotFoundError:
        print(f"ERROR: input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"ERROR: invalid JSON in {args.input}: {exc}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(findings, list):
        print("ERROR: input JSON must be a list of findings", file=sys.stderr)
        sys.exit(1)

    out_path = args.out or _default_out(args.input)

    print(f"validator.py — {len(findings)} findings, timeout={args.timeout}s, "
          f"dry_run={args.dry_run}")
    print(f"output -> {out_path}")
    print("-" * 70)

    results = []
    for i, finding in enumerate(findings):
        enriched = validate_finding(finding, args.timeout, args.dry_run)
        results.append(enriched)
        # 0.5s sleep between live calls to avoid abuse detection
        if not args.dry_run and i < len(findings) - 1:
            time.sleep(0.5)

    # Write output
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, ensure_ascii=False)

    # Summary
    from collections import Counter
    counts = Counter(r["validation_status"] for r in results)
    print("-" * 70)
    print(f"Summary: {dict(counts)}")
    print(f"Wrote {len(results)} records -> {out_path}")


if __name__ == "__main__":
    main()
