"""
_git_history_scan.py
Scans recently-pushed GitHub repositories' git commit histories for secrets.
"""

import json
import math
import os
import re
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent
OUTPUT_DIR = ROOT / "output"
OUTPUT_FILE = OUTPUT_DIR / "hunt_git_history.json"

# ---------------------------------------------------------------------------
# Token loading
# ---------------------------------------------------------------------------

def load_tokens():
    env_path = Path(r"C:\Users\aduad\tools\llm-rotate\.env")
    env_vars = {}
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            env_vars[k.strip()] = v.strip().strip('"').strip("'")

    tokens = []
    # Multi-token: GITHUB_TOKEN_1..N
    i = 1
    while True:
        key = f"GITHUB_TOKEN_{i}"
        val = os.environ.get(key) or env_vars.get(key)
        if val:
            tokens.append(val)
            i += 1
        else:
            break

    # Single token fallback
    if not tokens:
        val = os.environ.get("GITHUB_TOKEN") or env_vars.get("GITHUB_TOKEN")
        if val:
            tokens.append(val)

    return tokens


TOKENS = load_tokens()
_token_index = 0


def get_token():
    global _token_index
    if not TOKENS:
        return None
    tok = TOKENS[_token_index % len(TOKENS)]
    _token_index += 1
    return tok


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

PATTERNS = {
    "openai_key":     (re.compile(r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,}"),          "CRITICAL"),
    "anthropic_key":  (re.compile(r"sk-ant-[A-Za-z0-9_-]{90,}"),                          "HIGH"),
    "groq_key":       (re.compile(r"gsk_[A-Za-z0-9]{52}"),                                "HIGH"),
    "github_pat":     (re.compile(r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}"),   "CRITICAL"),
    "aws_access":     (re.compile(r"AKIA[0-9A-Z]{16}"),                                    "CRITICAL"),
    "aws_secret":     (re.compile(r"(?i)aws.{0,20}secret.{0,10}[=:]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"), "CRITICAL"),
    "stripe_live":    (re.compile(r"sk_live_[A-Za-z0-9]{24,}"),                           "CRITICAL"),
    "sendgrid_key":   (re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),          "HIGH"),
    "do_token":       (re.compile(r"dop_v1_[a-f0-9]{64}"),                                "HIGH"),
    "telegram_bot":   (re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}"),                         "HIGH"),
    "huggingface":    (re.compile(r"hf_[A-Za-z0-9]{34,}"),                                "HIGH"),
    "google_oauth":   (re.compile(r"GOCSPX-[A-Za-z0-9_-]{28}"),                           "CRITICAL"),
    "xai_key":        (re.compile(r"xai-[A-Za-z0-9]{80,}"),                               "HIGH"),
    "openrouter_key": (re.compile(r"sk-or-v1-[a-f0-9]{64}"),                              "HIGH"),
    "cerebras_key":   (re.compile(r"csk-[A-Za-z0-9]{48}"),                                "HIGH"),
    "ssh_private":    (re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"),  "CRITICAL"),
}

FP_HINTS = re.compile(
    r"example|test|changeme|xxxx|placeholder|dummy|sample", re.IGNORECASE
)

SLEEP_BETWEEN = 6  # seconds between API calls


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def mask_value(value: str) -> str:
    if len(value) <= 18:
        return value[:4] + "***"
    return value[:12] + "..." + value[-6:]


def make_headers(token=None):
    tok = token or get_token()
    h = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "github-secret-hunter",
    }
    if tok:
        h["Authorization"] = f"token {tok}"
    return h


def api_get(url, diff=False, retries=3):
    headers = make_headers()
    if diff:
        headers["Accept"] = "application/vnd.github.v3.diff"

    for attempt in range(retries):
        try:
            resp = requests.get(url, headers=headers, timeout=20)
            if resp.status_code == 200:
                return resp
            if resp.status_code in (429, 403):
                wait = 30 * (attempt + 1)
                print(f"  [RATE LIMIT] {resp.status_code} on {url} — sleeping {wait}s")
                time.sleep(wait)
                continue
            if resp.status_code == 404:
                return None
            print(f"  [WARN] HTTP {resp.status_code} for {url}")
            return None
        except requests.RequestException as exc:
            print(f"  [ERROR] Request failed: {exc}")
            time.sleep(10)

    return None


def scan_text(text, repo_full, commit_sha, commit_url):
    findings = []
    for pattern_name, (regex, severity) in PATTERNS.items():
        for match in regex.finditer(text):
            # For aws_secret, group 1 is the actual secret value
            if pattern_name == "aws_secret" and match.lastindex and match.lastindex >= 1:
                value = match.group(1)
            else:
                value = match.group(0)

            if FP_HINTS.search(value):
                continue

            entropy = shannon_entropy(value)
            if entropy < 3.5:
                continue

            masked = mask_value(value)
            findings.append({
                "pattern_name": pattern_name,
                "repo": repo_full,
                "commit_sha": commit_sha,
                "url": commit_url,
                "matched_masked": masked,
                "severity": severity,
                "entropy": round(entropy, 3),
                "source": "git_history",
            })

    return findings


# ---------------------------------------------------------------------------
# Core scanning logic
# ---------------------------------------------------------------------------

def get_recent_repos(max_repos=50):
    """Fetch recently pushed repos from GitHub Events API."""
    print("[*] Fetching recent push events from GitHub Events API...")
    url = "https://api.github.com/events?per_page=100"
    seen = set()
    repos = []

    page = 1
    while len(repos) < max_repos:
        paged_url = url if page == 1 else f"{url}&page={page}"
        resp = api_get(paged_url)
        if not resp:
            break

        events = resp.json()
        if not events:
            break

        for event in events:
            if event.get("type") != "PushEvent":
                continue
            repo_info = event.get("repo", {})
            repo_full = repo_info.get("name", "")
            if not repo_full or repo_full in seen:
                continue
            seen.add(repo_full)
            repos.append(repo_full)
            if len(repos) >= max_repos:
                break

        if len(events) < 100:
            break
        page += 1
        time.sleep(SLEEP_BETWEEN)

    print(f"[*] Collected {len(repos)} unique repos from push events.")
    return repos[:max_repos]


def get_commits(owner, repo, max_commits=20):
    url = f"https://api.github.com/repos/{owner}/{repo}/commits?per_page={max_commits}"
    resp = api_get(url)
    if not resp:
        return []
    try:
        return resp.json()
    except Exception:
        return []


def get_commit_diff(owner, repo, sha):
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    resp = api_get(url, diff=True)
    if not resp:
        return ""
    return resp.text


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    all_findings = []
    repos = get_recent_repos(max_repos=50)

    total_repos_scanned = 0
    total_commits_scanned = 0
    total_hits = 0

    for repo_full in repos:
        if "/" not in repo_full:
            continue
        owner, repo = repo_full.split("/", 1)

        print(f"\n[REPO] {repo_full}")
        time.sleep(SLEEP_BETWEEN)

        commits = get_commits(owner, repo, max_commits=20)
        if not commits:
            print("  [SKIP] No commits found or access denied.")
            continue

        total_repos_scanned += 1
        repo_hits = 0

        for commit_data in commits:
            sha = commit_data.get("sha", "")
            if not sha:
                continue

            commit_url = commit_data.get("html_url") or f"https://github.com/{repo_full}/commit/{sha}"
            time.sleep(SLEEP_BETWEEN)

            diff_text = get_commit_diff(owner, repo, sha)
            if not diff_text:
                continue

            total_commits_scanned += 1
            findings = scan_text(diff_text, repo_full, sha, commit_url)

            for f in findings:
                print(
                    f"  [HIT] {f['pattern_name']} | {f['severity']} | entropy={f['entropy']} "
                    f"| {f['matched_masked']} | {commit_url}"
                )
                repo_hits += 1
                total_hits += 1

            all_findings.extend(findings)

        print(f"  Commits scanned: {len(commits)} | Hits: {repo_hits}")

    # Write output
    OUTPUT_FILE.write_text(
        json.dumps(all_findings, indent=2, ensure_ascii=True),
        encoding="utf-8"
    )

    print("\n" + "=" * 60)
    print(f"Repos scanned    : {total_repos_scanned}")
    print(f"Commits scanned  : {total_commits_scanned}")
    print(f"Total hits       : {total_hits}")
    print(f"Output file      : {OUTPUT_FILE}")
    print("=" * 60)


if __name__ == "__main__":
    main()
