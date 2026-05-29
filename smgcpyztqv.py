"""
dork_gen.py — LLM-powered GitHub dork generator for secret hunting.

Usage:
  python dork_gen.py [--category openai|aws|github|all] [--count 20]
                     [--out config/extra_dorks.yaml] [--append-to config/queries.yaml]
                     [--dry-run]
"""

import sys
import os
import subprocess
import argparse
import textwrap
from pathlib import Path

import yaml  # PyYAML

# ── Paths ─────────────────────────────────────────────────────────────────────
HERE      = Path(__file__).parent
ROTATE_PY = Path(r"C:\Users\aduad\tools\llm-rotate\rotate.py")
ENV_FILE  = Path(r"C:\Users\aduad\tools\llm-rotate\.env")
QUERIES_YAML = HERE / "config" / "queries.yaml"

# ── GITHUB_TOKEN fallback ─────────────────────────────────────────────────────
def _load_env_file():
    """Parse KEY=VALUE lines from llm-rotate/.env into os.environ (no-overwrite)."""
    if not ENV_FILE.exists():
        return
    for raw in ENV_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

_load_env_file()

# ── Category definitions ───────────────────────────────────────────────────────
CATEGORIES = ["openai", "anthropic", "aws", "github", "huggingface", "groq", "generic_env"]

CATEGORY_LABELS = {
    "openai":      "OpenAI API keys (sk-, OPENAI_API_KEY, GPT, chatgpt token)",
    "anthropic":   "Anthropic/Claude API keys (ANTHROPIC_API_KEY, claude api, sk-ant-)",
    "aws":         "AWS credentials (AKIA, AWS_SECRET, aws_access_key_id)",
    "github":      "GitHub tokens (ghp_, GITHUB_TOKEN, personal access token)",
    "huggingface": "HuggingFace tokens (hf_, HUGGING_FACE, transformers token)",
    "groq":        "Groq API keys (GROQ_API_KEY, gsk_)",
    "generic_env": "generic leaked secrets (.env files, secrets.yaml, config with passwords)",
}

# Hardcoded fallback dorks (10 per category) — used if LLM call fails.
FALLBACK_DORKS: dict[str, list[str]] = {
    "openai": [
        'filename:.env "OPENAI_API_KEY=sk-"',
        'filename:config.py "openai.api_key"',
        'filename:secrets.yaml "openai_key"',
        'extension:ipynb "sk-" OPENAI',
        'filename:docker-compose.yml OPENAI_API_KEY sk-',
        'extension:env "OPENAI_API_KEY" "sk-proj-"',
        'path:.github/workflows OPENAI_API_KEY',
        'filename:.env.production "sk-" openai',
        'extension:py "openai.api_key = " sk-',
        'filename:settings.py OPENAI_API_KEY sk-',
    ],
    "anthropic": [
        'filename:.env "ANTHROPIC_API_KEY=sk-ant-"',
        'extension:py "anthropic.Anthropic" "sk-ant-"',
        'filename:secrets.yaml ANTHROPIC_API_KEY',
        'extension:ipynb "sk-ant-" anthropic',
        'filename:.env.local "ANTHROPIC_API_KEY"',
        'path:.github/workflows ANTHROPIC_API_KEY',
        'filename:config.json "anthropic_api_key"',
        'extension:env "ANTHROPIC" "sk-ant-api03"',
        'filename:docker-compose.yml ANTHROPIC_API_KEY',
        'filename:settings.py "ANTHROPIC_API_KEY"',
    ],
    "aws": [
        'filename:.env "AWS_ACCESS_KEY_ID=AKIA"',
        'filename:credentials "aws_access_key_id"',
        'extension:py "boto3" "AKIA" aws_secret',
        'filename:.aws/credentials aws_access_key_id',
        'extension:yaml "aws_access_key_id: AKIA"',
        'filename:terraform.tfvars "access_key" "secret_key"',
        'extension:json "aws_access_key" "AKIA"',
        'path:.github/workflows "AWS_SECRET_ACCESS_KEY"',
        'filename:docker-compose.yml "AWS_ACCESS_KEY_ID"',
        'extension:cfg "aws_access_key_id" "AKIA"',
    ],
    "github": [
        'filename:.env "GITHUB_TOKEN=ghp_"',
        'extension:py "github_token" "ghp_"',
        'filename:config.yaml "github_token" ghp_',
        'extension:env "GH_TOKEN=ghp_"',
        'path:.github/workflows "GITHUB_PAT"',
        'filename:.env.local GITHUB_TOKEN ghp_',
        'extension:json "github_token" "ghp_"',
        'filename:secrets.yaml "github_token"',
        'extension:sh "GITHUB_TOKEN" "ghp_"',
        'filename:docker-compose.yml GITHUB_TOKEN ghp_',
    ],
    "huggingface": [
        'filename:.env "HUGGING_FACE_HUB_TOKEN=hf_"',
        'extension:py "huggingface_hub" "hf_" token',
        'filename:config.yaml "hf_token"',
        'extension:ipynb "hf_" HuggingFace token',
        'filename:.env.example "HUGGINGFACE_TOKEN"',
        'path:.github/workflows HUGGING_FACE_HUB_TOKEN',
        'extension:env "HF_TOKEN=hf_"',
        'filename:secrets.yaml "hf_token"',
        'extension:py "use_auth_token" "hf_"',
        'filename:docker-compose.yml "HUGGING_FACE_HUB_TOKEN"',
    ],
    "groq": [
        'filename:.env "GROQ_API_KEY=gsk_"',
        'extension:py "groq" "gsk_" api_key',
        'filename:config.yaml "groq_api_key"',
        'extension:ipynb "gsk_" groq',
        'filename:.env.local GROQ_API_KEY',
        'path:.github/workflows GROQ_API_KEY',
        'extension:env "GROQ_API_KEY"',
        'filename:secrets.yaml "groq_key"',
        'extension:sh "GROQ_API_KEY" "gsk_"',
        'filename:docker-compose.yml GROQ_API_KEY',
    ],
    "generic_env": [
        'filename:.env "password=" "secret="',
        'filename:secrets.yaml "api_key:" "password:"',
        'extension:env "DB_PASSWORD" "SECRET_KEY"',
        'filename:.env.production "DATABASE_URL" password',
        'filename:docker-compose.yml "POSTGRES_PASSWORD"',
        'path:.github/workflows "secret" "api_key"',
        'filename:.env.example "SECRET_KEY" "API_KEY"',
        'extension:yaml "smtp_password" "db_password"',
        'filename:config.ini "password=" "secret="',
        'extension:json "api_key" "secret_key" "password"',
    ],
}


# ── Load existing queries from queries.yaml ────────────────────────────────────
def load_existing_queries(path: Path) -> set[str]:
    """Return a set of all existing query strings from queries.yaml."""
    if not path.exists():
        return set()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return set()
    existing: set[str] = set()
    if not isinstance(data, dict):
        return existing
    cats = data.get("categories", {})
    for entries in cats.values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict):
                q = entry.get("q", "")
                if q:
                    existing.add(q.strip())
            elif isinstance(entry, str):
                existing.add(entry.strip())
    return existing


# ── LLM call via llm-rotate ────────────────────────────────────────────────────
def call_llm(prompt: str, timeout: int = 45) -> str | None:
    """Call rotate.py with TEAM_FAST; return stdout or None on failure."""
    try:
        result = subprocess.run(
            [sys.executable, str(ROTATE_PY), prompt, "--team", "TEAM_FAST"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        return None
    except subprocess.TimeoutExpired:
        print(f"  [warn] llm-rotate timed out after {timeout}s", file=sys.stderr)
        return None
    except Exception as exc:
        print(f"  [warn] llm-rotate error: {exc}", file=sys.stderr)
        return None


# ── Build LLM prompt ──────────────────────────────────────────────────────────
def build_prompt(category: str, count: int, existing_queries: set[str]) -> str:
    label = CATEGORY_LABELS.get(category, category)
    # Sample up to 10 known queries as "don't repeat" examples
    sample = sorted(existing_queries)[:10]
    sample_block = "\n".join(f"  {q}" for q in sample) if sample else "  (none yet)"

    return textwrap.dedent(f"""\
        You are a GitHub secret-hunting expert. Generate {count} unique GitHub code search dork queries to find leaked {label} credentials in public repositories.

        Format: one query per line, just the raw search string (no explanation, no numbering, no bullet points).
        Focus on: .env files, config files, docker-compose, CI/CD yaml, Jupyter notebooks, Python scripts.

        Known effective patterns (do NOT repeat these exact ones):
        {sample_block}

        Generate NEW high-signal queries not in the above list. Output only the raw query strings, one per line.
    """).strip()


# ── Parse LLM response ────────────────────────────────────────────────────────
def parse_lines(text: str, existing: set[str], category: str) -> list[str]:
    """Clean and filter LLM output lines into valid new dork queries."""
    seen_lower: set[str] = {q.lower() for q in existing}
    result: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        # Strip leading numbering like "1." "1)" "-" "*"
        for prefix in ("- ", "* "):
            if line.startswith(prefix):
                line = line[len(prefix):].strip()
        if line and line[0].isdigit():
            dot = line.find(".")
            paren = line.find(")")
            cut = -1
            if dot != -1 and dot < 4:
                cut = dot
            if paren != -1 and paren < 4:
                cut = paren if cut == -1 else min(cut, paren)
            if cut != -1:
                line = line[cut + 1:].strip()

        # Quality filter
        if len(line) < 15:
            continue
        if line.lower() in seen_lower:
            continue
        words = line.split()
        if len(words) < 2:
            continue
        # Reject pure explanation lines
        if line.startswith("#") or line.lower().startswith("here are"):
            continue

        seen_lower.add(line.lower())
        result.append(line)
    return result


# ── Generate dorks for one category ───────────────────────────────────────────
def generate_for_category(
    category: str,
    count: int,
    existing: set[str],
    dry_run: bool = False,
    verbose: bool = True,
) -> list[dict]:
    """
    Call LLM (or use fallback) and return list of YAML-ready dork dicts.
    Each dict: {q, kind, max, qualifiers, category, description}
    """
    if verbose:
        print(f"[{category}] generating {count} dorks via LLM-rotate...")

    llm_text: str | None = None
    if not dry_run:
        prompt = build_prompt(category, count, existing)
        llm_text = call_llm(prompt)

    if llm_text:
        raw_queries = parse_lines(llm_text, existing, category)
        if verbose:
            print(f"  -> LLM returned {len(raw_queries)} valid new queries")
    else:
        if not dry_run:
            print(f"  [warn] LLM call failed — using fallback dorks", file=sys.stderr)
        raw_queries = [
            q for q in FALLBACK_DORKS.get(category, [])
            if q.strip().lower() not in {e.lower() for e in existing}
        ]
        if verbose:
            print(f"  -> fallback: {len(raw_queries)} queries")

    # Trim to requested count
    raw_queries = raw_queries[:count]

    entries = []
    for q in raw_queries:
        entries.append({
            "q": q,
            "kind": "code",
            "max": 30,
            "qualifiers": {},
            "category": "auto_generated",
            "description": f"LLM-generated ({category})",
        })
    return entries


# ── YAML serialization ─────────────────────────────────────────────────────────
def _dump_yaml(data: dict) -> str:
    """Dump dict as YAML with inline dicts on one line (no flow style for top level)."""
    # Build the output manually so dork entries stay compact.
    lines = ["categories:"]
    cats = data.get("categories", {})
    for cat_name, entries in cats.items():
        lines.append(f"  {cat_name}:")
        for e in entries:
            q = e["q"].replace('"', '\\"')
            qualifiers = e.get("qualifiers", {})
            if qualifiers:
                q_str = ", ".join(f'{k}: "{v}"' for k, v in qualifiers.items())
                quals_part = f", qualifiers: {{{q_str}}}"
            else:
                quals_part = ", qualifiers: {}"
            max_val = e.get("max", 30)
            kind = e.get("kind", "code")
            cat_label = e.get("category", "auto_generated")
            desc = e.get("description", "LLM-generated")
            lines.append(
                f'    - {{q: "{q}", kind: {kind}, max: {max_val}{quals_part},'
                f' category: "{cat_label}", description: "{desc}"}}'
            )
    return "\n".join(lines) + "\n"


# ── Write extra_dorks.yaml ─────────────────────────────────────────────────────
def write_extra_dorks(all_entries: dict[str, list[dict]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    data = {"categories": all_entries}
    out_path.write_text(_dump_yaml(data), encoding="utf-8")
    print(f"Wrote {sum(len(v) for v in all_entries.values())} entries -> {out_path}")


# ── Append to existing queries.yaml ───────────────────────────────────────────
def append_to_queries_yaml(all_entries: dict[str, list[dict]], target: Path) -> None:
    """Append new LLM-generated entries as a new 'secret_hunting' block."""
    if not target.exists():
        print(f"  [warn] --append-to target not found: {target}", file=sys.stderr)
        return

    lines = target.read_text(encoding="utf-8").splitlines()
    additions: list[str] = []
    additions.append("")
    additions.append("  # --- auto-generated by dork_gen.py ---")

    for cat_name, entries in all_entries.items():
        if not entries:
            continue
        additions.append(f"  secret_{cat_name}:")
        for e in entries:
            q = e["q"].replace('"', '\\"')
            max_val = e.get("max", 30)
            kind = e.get("kind", "code")
            additions.append(
                f'    - {{q: "{q}", kind: {kind}, max: {max_val},'
                f' qualifiers: {{}}, category: "auto_generated", description: "LLM-generated"}}'
            )

    target.write_text("\n".join(lines + additions) + "\n", encoding="utf-8")
    added = sum(len(v) for v in all_entries.values())
    print(f"Appended {added} entries -> {target}")


# ── CLI ────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Generate GitHub secret-hunting dork queries via LLM.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--category",
        default="all",
        help="Category to generate for: openai|anthropic|aws|github|huggingface|groq|generic_env|all",
    )
    parser.add_argument("--count", type=int, default=20, help="Queries to generate per category")
    parser.add_argument(
        "--out",
        default=str(HERE / "config" / "extra_dorks.yaml"),
        help="Output YAML file (default: config/extra_dorks.yaml)",
    )
    parser.add_argument(
        "--append-to",
        dest="append_to",
        default=None,
        help="Append new entries to this existing queries.yaml",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be generated (uses fallback dorks, no LLM call)",
    )
    args = parser.parse_args()

    # Resolve category list
    if args.category == "all":
        cats_to_run = CATEGORIES
    elif args.category in CATEGORIES:
        cats_to_run = [args.category]
    else:
        print(
            f"Unknown category '{args.category}'. Choose from: {', '.join(CATEGORIES)} or all",
            file=sys.stderr,
        )
        sys.exit(1)

    existing = load_existing_queries(QUERIES_YAML)
    out_path = Path(args.out)

    all_generated: dict[str, list[dict]] = {}

    for cat in cats_to_run:
        entries = generate_for_category(
            cat,
            args.count,
            existing,
            dry_run=args.dry_run,
        )
        all_generated[cat] = entries
        # Update existing set so later categories don't duplicate
        for e in entries:
            existing.add(e["q"])

        if args.dry_run:
            print(f"  [dry-run] Would write {len(entries)} entries for '{cat}':")
            for e in entries[:5]:
                print(f"    {e['q']}")
            if len(entries) > 5:
                print(f"    ... (+{len(entries) - 5} more)")

    total = sum(len(v) for v in all_generated.values())
    print(f"\nTotal generated: {total} entries across {len(cats_to_run)} categor(y/ies)")

    if args.dry_run:
        print("[dry-run] No files written.")
        return

    write_extra_dorks(all_generated, out_path)

    if args.append_to:
        append_to_queries_yaml(all_generated, Path(args.append_to))


if __name__ == "__main__":
    main()
