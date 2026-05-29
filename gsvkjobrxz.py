"""
llm_inject.py — watch found_agents/found_keys.env and inject discovered API keys
into the llm-rotate rotation.

CLI:
  python llm_inject.py [--source found_agents/found_keys.env]
                       [--test-first]
                       [--dry-run]
                       [--team TEAM_FREE|TEAM_SMART|all]

Providers read from rotate.py PROVIDERS list; fallback hardcoded below.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRAPER_ROOT   = Path(__file__).parent
LLM_ROTATE_DIR = Path(r"C:\Users\aduad\tools\llm-rotate")
LLM_ENV_FILE   = LLM_ROTATE_DIR / ".env"
TEAMS_FILE     = LLM_ROTATE_DIR / "teams.json"
FOUND_TEAMS_FILE = LLM_ROTATE_DIR / "found_teams.yaml"
LOG_DIR        = SCRAPER_ROOT / "logs"
LOG_FILE       = LOG_DIR / "llm_inject.log"
DEFAULT_SOURCE = SCRAPER_ROOT / "found_agents" / "found_keys.env"

SECTION_HEADER = "# === FOUND KEYS (github-scraper) ==="

# ---------------------------------------------------------------------------
# Provider → env-var mapping (built from rotate.py PROVIDERS list + fallback)
# ---------------------------------------------------------------------------

# Derived from rotate.py PROVIDERS tuple: (id, name, base_url, model, key_env, rpm)
ROTATE_PROVIDER_MAP: dict[str, str] = {
    "cerebras":      "CEREBRAS_API_KEY",
    "groq":          "GROQ_API_KEY",
    "sambanova":     "SAMBANOVA_API_KEY",
    "gemini":        "GEMINI_API_KEY",
    "openrouter":    "OPENROUTER_API_KEY",
    "mistral":       "MISTRAL_API_KEY",
    "cohere":        "COHERE_API_KEY",
    "together":      "TOGETHER_API_KEY",
    "novita":        "NOVITA_API_KEY",
    "deepinfra":     "DEEPINFRA_API_KEY",
    "github_models": "GITHUB_TOKEN",
    "cloudflare":    "CLOUDFLARE_API_KEY",
    "huggingface":   "HF_API_KEY",
    "perplexity":    "PERPLEXITY_API_KEY",
    "xai":           "XAI_API_KEY",
}

# Additional prefix → env-var mapping for keys found in .env files
# Key: normalized prefix (lowercase, no underscores). Value: (provider_id, env_var)
PREFIX_TO_PROVIDER: dict[str, tuple[str, str]] = {
    # OpenAI
    "openaiapi":         ("openai",      "OPENAI_API_KEY"),
    "openai":            ("openai",      "OPENAI_API_KEY"),
    # Anthropic
    "anthropicapi":      ("anthropic",   "ANTHROPIC_API_KEY"),
    "anthropic":         ("anthropic",   "ANTHROPIC_API_KEY"),
    # Groq
    "groqapi":           ("groq",        "GROQ_API_KEY"),
    "groq":              ("groq",        "GROQ_API_KEY"),
    # HuggingFace
    "hf":                ("huggingface", "HF_API_KEY"),
    "huggingface":       ("huggingface", "HF_API_KEY"),
    "huggingfacetoken":  ("huggingface", "HF_API_KEY"),
    # Cohere
    "cohereapi":         ("cohere",      "COHERE_API_KEY"),
    "cohere":            ("cohere",      "COHERE_API_KEY"),
    # Mistral
    "mistralapi":        ("mistral",     "MISTRAL_API_KEY"),
    "mistral":           ("mistral",     "MISTRAL_API_KEY"),
    # xAI
    "xai":               ("xai",         "XAI_API_KEY"),
    # Together
    "together":          ("together",    "TOGETHER_API_KEY"),
    "togetherapi":       ("together",    "TOGETHER_API_KEY"),
    # Replicate
    "replicate":         ("replicate",   "REPLICATE_API_TOKEN"),
    "replicateapi":      ("replicate",   "REPLICATE_API_TOKEN"),
    # Google / Gemini
    "gemini":            ("gemini",      "GEMINI_API_KEY"),
    "googleapi":         ("gemini",      "GEMINI_API_KEY"),
    "google":            ("gemini",      "GEMINI_API_KEY"),
    # OpenRouter
    "openrouter":        ("openrouter",  "OPENROUTER_API_KEY"),
    # Perplexity
    "perplexity":        ("perplexity",  "PERPLEXITY_API_KEY"),
    # Cerebras
    "cerebras":          ("cerebras",    "CEREBRAS_API_KEY"),
    # SambaNova
    "sambanova":         ("sambanova",   "SAMBANOVA_API_KEY"),
    # DeepInfra
    "deepinfra":         ("deepinfra",   "DEEPINFRA_API_KEY"),
    # Novita
    "novita":            ("novita",      "NOVITA_API_KEY"),
    # Cloudflare
    "cloudflare":        ("cloudflare",  "CLOUDFLARE_API_KEY"),
    # GitHub
    "githubtoken":       ("github_models", "GITHUB_TOKEN"),
    "github":            ("github_models", "GITHUB_TOKEN"),
}


def _normalize_key_name(raw: str) -> str:
    """Normalize a key name for prefix lookup: lowercase, strip common suffixes."""
    import re
    s = raw.lower()
    # Strip any trailing _found_NNN or _NNN patterns added by api_integrator FIRST
    s = re.sub(r"_found_\d+$", "", s)
    s = re.sub(r"_\d+$", "", s)
    # Strip trailing API key suffixes to isolate provider prefix
    for suffix in ("_api_key", "_api_token", "_token", "_key", "_secret",
                   "apikey", "apitoken", "token", "key", "secret"):
        if s.endswith(suffix):
            s = s[: -len(suffix)]
            break
    # Strip underscores for pure prefix matching
    return s.replace("_", "")


def _detect_provider(raw_key_name: str) -> tuple[str | None, str | None]:
    """
    Return (provider_id, env_var) for a raw KEY name from found_keys.env.
    Returns (None, None) if unrecognised.
    """
    norm = _normalize_key_name(raw_key_name)
    return PREFIX_TO_PROVIDER.get(norm, (None, None))


# ---------------------------------------------------------------------------
# Masking
# ---------------------------------------------------------------------------


def _mask(value: str) -> str:
    """Show first 8 + '...' + last 4 chars."""
    if len(value) <= 14:
        return value[:8] + "..."
    return value[:8] + "..." + value[-4:]


# ---------------------------------------------------------------------------
# .env I/O
# ---------------------------------------------------------------------------


def _load_env_keys(path: Path) -> dict[str, str]:
    """Parse a .env file; return {KEY: value}. Comments and blanks skipped."""
    result: dict[str, str] = {}
    if not path.exists():
        return result
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, _, v = line.partition("=")
                result[k.strip()] = v.strip().strip('"').strip("'")
    return result


def _env_has_section(path: Path) -> bool:
    """Check whether SECTION_HEADER already exists in the .env file."""
    if not path.exists():
        return False
    with open(path, encoding="utf-8") as fh:
        return SECTION_HEADER in fh.read()


def _append_to_env(path: Path, key: str, value: str, dry_run: bool) -> bool:
    """
    Append KEY=value under the FOUND KEYS section.
    Returns True if appended (or would append in dry-run), False if key already existed.
    """
    existing = _load_env_keys(path)
    if key in existing:
        return False  # already present — do not overwrite

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    needs_header = not _env_has_section(path)

    if dry_run:
        print(f"  [DRY-RUN] would append to {path}:")
        if needs_header:
            print(f"    {SECTION_HEADER}")
        print(f"    # injected by llm_inject.py {ts}")
        print(f"    {key}={_mask(value)}")
        return True

    with open(path, "a", encoding="utf-8") as fh:
        if needs_header:
            fh.write(f"\n{SECTION_HEADER}\n")
        fh.write(f"# injected by llm_inject.py {ts}\n")
        fh.write(f"{key}={value}\n")
    return True


# ---------------------------------------------------------------------------
# found_keys.env parser
# ---------------------------------------------------------------------------


def _parse_found_keys(source: Path) -> list[dict]:
    """
    Parse found_keys.env.  Returns list of dicts:
      {raw_key_name, value, provider_id, env_var}
    Skips unrecognised providers.
    """
    results = []
    if not source.exists():
        print(f"[ERROR] source file not found: {source}", file=sys.stderr)
        return results

    with open(source, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            raw_key, _, raw_val = line.partition("=")
            raw_key = raw_key.strip()
            raw_val = raw_val.strip().strip('"').strip("'")
            if not raw_val:
                continue
            provider_id, env_var = _detect_provider(raw_key)
            results.append({
                "raw_key_name": raw_key,
                "value": raw_val,
                "provider_id": provider_id,
                "env_var": env_var,
            })
    return results


# ---------------------------------------------------------------------------
# Live-test validators (inlined from validator.py patterns)
# ---------------------------------------------------------------------------


def _http_get(url: str, headers: dict, timeout: int) -> tuple[int, bytes]:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        body = b""
        try:
            body = exc.read()
        except Exception:
            pass
        return exc.code, body
    except Exception as exc:
        return 0, str(exc).encode()


def _http_post(url: str, headers: dict, body: bytes, timeout: int) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        rb = b""
        try:
            rb = exc.read()
        except Exception:
            pass
        return exc.code, rb
    except Exception as exc:
        return 0, str(exc).encode()


LIVE_TESTERS: dict[str, callable] = {}


def _reg(name):
    def deco(fn):
        LIVE_TESTERS[name] = fn
        return fn
    return deco


@_reg("openai")
def _test_openai(key: str, timeout: int = 8) -> tuple[bool, str]:
    code, _ = _http_get(
        "https://api.openai.com/v1/models",
        {"Authorization": f"Bearer {key}", "User-Agent": "llm_inject/1.0"},
        timeout,
    )
    if code == 200:
        return True, "VALID"
    if code == 401:
        return False, "INVALID"
    if code == 429:
        return False, "RATE_LIMITED"
    return False, f"HTTP {code}"


@_reg("anthropic")
def _test_anthropic(key: str, timeout: int = 8) -> tuple[bool, str]:
    payload = json.dumps({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 1,
        "messages": [{"role": "user", "content": "hi"}],
    }).encode()
    code, _ = _http_post(
        "https://api.anthropic.com/v1/messages",
        {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
            "User-Agent": "llm_inject/1.0",
        },
        payload,
        timeout,
    )
    if code == 200:
        return True, "VALID"
    if code in (401, 403):
        return False, "INVALID"
    if code == 429:
        return False, "RATE_LIMITED"
    return False, f"HTTP {code}"


@_reg("groq")
def _test_groq(key: str, timeout: int = 8) -> tuple[bool, str]:
    code, _ = _http_get(
        "https://api.groq.com/openai/v1/models",
        {"Authorization": f"Bearer {key}", "User-Agent": "llm_inject/1.0"},
        timeout,
    )
    if code == 200:
        return True, "VALID"
    if code == 401:
        return False, "INVALID"
    if code == 429:
        return False, "RATE_LIMITED"
    return False, f"HTTP {code}"


@_reg("huggingface")
def _test_huggingface(key: str, timeout: int = 8) -> tuple[bool, str]:
    code, _ = _http_get(
        "https://huggingface.co/api/whoami",
        {"Authorization": f"Bearer {key}", "User-Agent": "llm_inject/1.0"},
        timeout,
    )
    if code == 200:
        return True, "VALID"
    if code == 401:
        return False, "INVALID"
    if code == 429:
        return False, "RATE_LIMITED"
    return False, f"HTTP {code}"


@_reg("mistral")
def _test_mistral(key: str, timeout: int = 8) -> tuple[bool, str]:
    code, _ = _http_get(
        "https://api.mistral.ai/v1/models",
        {"Authorization": f"Bearer {key}", "User-Agent": "llm_inject/1.0"},
        timeout,
    )
    if code == 200:
        return True, "VALID"
    if code == 401:
        return False, "INVALID"
    if code == 429:
        return False, "RATE_LIMITED"
    return False, f"HTTP {code}"


@_reg("cohere")
def _test_cohere(key: str, timeout: int = 8) -> tuple[bool, str]:
    code, _ = _http_get(
        "https://api.cohere.ai/v1/models",
        {"Authorization": f"Bearer {key}", "User-Agent": "llm_inject/1.0"},
        timeout,
    )
    if code == 200:
        return True, "VALID"
    if code == 401:
        return False, "INVALID"
    if code == 429:
        return False, "RATE_LIMITED"
    return False, f"HTTP {code}"


@_reg("xai")
def _test_xai(key: str, timeout: int = 8) -> tuple[bool, str]:
    code, _ = _http_get(
        "https://api.x.ai/v1/models",
        {"Authorization": f"Bearer {key}", "User-Agent": "llm_inject/1.0"},
        timeout,
    )
    if code == 200:
        return True, "VALID"
    if code in (401, 403):
        return False, "INVALID"
    if code == 429:
        return False, "RATE_LIMITED"
    return False, f"HTTP {code}"


@_reg("together")
def _test_together(key: str, timeout: int = 8) -> tuple[bool, str]:
    code, _ = _http_get(
        "https://api.together.xyz/v1/models",
        {"Authorization": f"Bearer {key}", "User-Agent": "llm_inject/1.0"},
        timeout,
    )
    if code == 200:
        return True, "VALID"
    if code == 401:
        return False, "INVALID"
    if code == 429:
        return False, "RATE_LIMITED"
    return False, f"HTTP {code}"


@_reg("openrouter")
def _test_openrouter(key: str, timeout: int = 8) -> tuple[bool, str]:
    code, _ = _http_get(
        "https://openrouter.ai/api/v1/models",
        {"Authorization": f"Bearer {key}", "User-Agent": "llm_inject/1.0"},
        timeout,
    )
    if code == 200:
        return True, "VALID"
    if code == 401:
        return False, "INVALID"
    if code == 429:
        return False, "RATE_LIMITED"
    return False, f"HTTP {code}"


@_reg("perplexity")
def _test_perplexity(key: str, timeout: int = 8) -> tuple[bool, str]:
    # Perplexity has no public /models list; do a minimal chat call
    payload = json.dumps({
        "model": "sonar",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 1,
    }).encode()
    code, _ = _http_post(
        "https://api.perplexity.ai/chat/completions",
        {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "User-Agent": "llm_inject/1.0",
        },
        payload,
        timeout,
    )
    if code == 200:
        return True, "VALID"
    if code in (401, 403):
        return False, "INVALID"
    if code == 429:
        return False, "RATE_LIMITED"
    return False, f"HTTP {code}"


@_reg("gemini")
def _test_gemini(key: str, timeout: int = 8) -> tuple[bool, str]:
    url = f"https://generativelanguage.googleapis.com/v1beta/models?key={key}"
    code, _ = _http_get(url, {"User-Agent": "llm_inject/1.0"}, timeout)
    if code == 200:
        return True, "VALID"
    if code in (400, 401, 403):
        return False, "INVALID"
    if code == 429:
        return False, "RATE_LIMITED"
    return False, f"HTTP {code}"


# Providers with no simple check — mark as SKIPPED
_NO_TESTER = {"cerebras", "sambanova", "novita", "deepinfra", "cloudflare",
              "github_models", "replicate"}


def _live_test(provider_id: str, value: str, timeout: int = 8) -> tuple[bool, str]:
    """Run live test for a provider. Returns (is_live, status_str)."""
    if provider_id in _NO_TESTER:
        return True, "SKIPPED_NO_TESTER"
    tester = LIVE_TESTERS.get(provider_id)
    if tester is None:
        return True, "SKIPPED_UNKNOWN_PROVIDER"
    try:
        return tester(value, timeout)
    except Exception as exc:
        return False, f"ERROR:{exc}"


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def _log(provider_id: str, env_var: str, value: str, status: str, dry_run: bool):
    LOG_DIR.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    masked = _mask(value)
    mode = "DRY-RUN" if dry_run else "LIVE"
    line = f"{ts}\t{mode}\t{provider_id}\t{env_var}\t{masked}\t{status}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as fh:
        fh.write(line)


# ---------------------------------------------------------------------------
# Team YAML writer
# ---------------------------------------------------------------------------


def _write_found_teams(team_name: str, provider_ids: list[str], dry_run: bool):
    """
    Append discovered provider IDs to found_teams.yaml in the llm-rotate format.
    Mirrors teams.json structure but in YAML (hand-built, no PyYAML dependency).
    """
    team_key = team_name.upper()
    if not team_key.startswith("TEAM_"):
        team_key = "TEAM_" + team_key

    if dry_run:
        print(f"  [DRY-RUN] would write {FOUND_TEAMS_FILE}:")
        print(f"    {team_key}: {provider_ids}")
        return

    # Load existing teams from teams.json to merge
    existing_teams: dict = {}
    if TEAMS_FILE.exists():
        try:
            existing_teams = json.loads(TEAMS_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass

    # Build set of providers to add (those that rotate.py already knows)
    known_providers = set(ROTATE_PROVIDER_MAP.keys())
    to_add = [p for p in provider_ids if p in known_providers]

    # Build YAML content (simple — no PyYAML required)
    lines = [
        "# found_teams.yaml — generated by llm_inject.py",
        f"# Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "#",
        "# Add these providers to the named team in rotate.py --team invocations.",
        "# Merge with teams.json manually or extend rotate.py to load this file.",
        "",
    ]

    # Existing content from teams.json as YAML reference
    lines.append("# --- reference teams (from teams.json) ---")
    for k, v in existing_teams.items():
        lines.append(f"# {k}: [{', '.join(v)}]")
    lines.append("")

    # New/updated team entry
    lines.append("# --- found-key teams ---")
    if team_key == "all":
        # Add to all known teams
        for tk in existing_teams:
            merged = list(dict.fromkeys(existing_teams.get(tk, []) + to_add))
            lines.append(f"{tk}: [{', '.join(merged)}]")
    else:
        base = existing_teams.get(team_key, [])
        merged = list(dict.fromkeys(base + to_add))
        lines.append(f"{team_key}: [{', '.join(merged)}]")
    lines.append("")

    FOUND_TEAMS_FILE.write_text("\n".join(lines), encoding="utf-8")
    print(f"  [team] wrote {FOUND_TEAMS_FILE}  ({team_key}: {to_add})")


# ---------------------------------------------------------------------------
# Main injection loop
# ---------------------------------------------------------------------------


def run(source: Path, test_first: bool, dry_run: bool, team: str | None,
        live_timeout: int = 8):
    print(f"llm_inject.py  source={source}  test_first={test_first}  "
          f"dry_run={dry_run}  team={team}")
    print("-" * 70)

    entries = _parse_found_keys(source)
    if not entries:
        print("[warn] no KEY=value pairs found in source file.")
        return

    injected:    list[str] = []
    failed_test: list[str] = []
    skipped:     list[str] = []
    unknown:     list[str] = []
    blocked:     list[str] = []

    discovered_providers: list[str] = []

    for entry in entries:
        raw_name    = entry["raw_key_name"]
        value       = entry["value"]
        provider_id = entry["provider_id"]
        env_var     = entry["env_var"]

        if provider_id is None:
            print(f"  [?]  {raw_name} — unrecognised provider, skipping")
            _log("UNKNOWN", raw_name, value, "SKIP:UNKNOWN_PROVIDER", dry_run)
            unknown.append(raw_name)
            continue

        masked = _mask(value)
        print(f"  [{provider_id}]  {raw_name} = {masked}  (env_var={env_var})")

        # --- Live test ---
        if test_first:
            live, status = _live_test(provider_id, value, live_timeout)
            if not live:
                print(f"    -> live-test FAILED: {status}")
                _log(provider_id, env_var, value, f"FAIL:{status}", dry_run)
                failed_test.append(raw_name)
                continue
            print(f"    -> live-test OK: {status}")
            # Rate-limit courtesy
            time.sleep(0.5)

        # --- Check if target env_var already in .env ---
        existing = _load_env_keys(LLM_ENV_FILE)
        if env_var in existing:
            print(f"    -> BLOCKED: {env_var} already exists in {LLM_ENV_FILE}")
            _log(provider_id, env_var, value, "SKIP:ALREADY_EXISTS", dry_run)
            blocked.append(raw_name)
            continue

        # --- Append ---
        appended = _append_to_env(LLM_ENV_FILE, env_var, value, dry_run)
        if appended:
            status_str = "DRY_INJECTED" if dry_run else "INJECTED"
            _log(provider_id, env_var, value, status_str, dry_run)
            print(f"    -> {'(DRY) ' if dry_run else ''}injected {env_var}")
            injected.append(raw_name)
            discovered_providers.append(provider_id)
        else:
            # _append_to_env returned False = key already in file (race condition)
            _log(provider_id, env_var, value, "SKIP:ALREADY_EXISTS", dry_run)
            blocked.append(raw_name)

    # --- Team config ---
    if team and discovered_providers:
        _write_found_teams(team, discovered_providers, dry_run)

    # --- Summary ---
    print("-" * 70)
    print(f"Injected:      {len(injected)}  {injected}")
    print(f"Blocked (dup): {len(blocked)}  {blocked}")
    print(f"Failed test:   {len(failed_test)}  {failed_test}")
    print(f"Skipped:       {len(skipped)}  {skipped}")
    print(f"Unknown prov.: {len(unknown)}  {unknown}")
    print(f"Log:           {LOG_FILE}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Inject discovered API keys from found_keys.env into llm-rotate."
    )
    parser.add_argument(
        "--source",
        default=str(DEFAULT_SOURCE),
        help=f"Path to found_keys.env (default: {DEFAULT_SOURCE})",
    )
    parser.add_argument(
        "--test-first",
        action="store_true",
        help="Make a minimal API call to confirm each key is live before injecting.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be injected without writing to .env.",
    )
    parser.add_argument(
        "--team",
        default=None,
        metavar="TEAM_FREE|TEAM_SMART|all",
        help="Also write found_teams.yaml adding discovered providers to this team.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=8,
        help="Timeout in seconds for live-test API calls (default: 8).",
    )
    args = parser.parse_args()

    run(
        source=Path(args.source),
        test_first=args.test_first,
        dry_run=args.dry_run,
        team=args.team,
        live_timeout=args.timeout,
    )


if __name__ == "__main__":
    main()
